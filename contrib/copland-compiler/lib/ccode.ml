(**
 * Copyright 2024 United States Government
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *)

(** Quick and dirty C syntax types and serialzation. Definitely not
    complete, but should be good enough to generate c code of
    workflows.

    The {!module:Primitives} module defines basic of C syntax, the
    outer module provides a higher-level interface for building up
    functions implementing workflows using the {!module:State} monad.
*)

open Core

(** Basic C syntax types *)
module Primitives = struct
    type ident = string (** C identifiers *)

    (** Binary operators in C *)
    type binop = | Add | Sub | Mul | Div | Mod | Land | Lor | Band | Bor | Bxor | Lt  | Le | Neq | Eq | Gt | Ge | Deref

    (** Convert a binop to the infix C operator (e.g., [c_of_binop Add = "+"]). *)
    let c_of_binop = function
        | Add -> "+"
        | Sub -> "-"
        | Mul -> "*"
        | Div -> "/"
        | Mod -> "%"
        | Land -> "&&"
        | Lor -> "||"
        | Band -> "&"
        | Bor -> "|"
        | Bxor -> "^"
        | Lt  -> "<"
        | Le  -> "<="
        | Neq  -> "!="
        | Eq  -> "=="
        | Gt  -> ">"
        | Ge  -> ">="
        | Deref -> "->"

    (** Unary operators in C *)
    type unop = | AddrOf | PointsTo | Neg | Lnot | Bnot

    (** Convert a unary operator to the prefix C operator (e.g., [c_of_unop AddrOf = "&"]). *)
    let c_of_unop = function
        | AddrOf -> "&"
        | PointsTo -> "*"
        | Neg -> "-"
        | Lnot -> "!"
        | Bnot -> "~"

    (** C style expressions. *)
    type expr =
        | Var of ident
        | StringLit of string
        | IntLit of int
        | EnumLit of string
        | BinExpr of binop * expr * expr
        | UnExpr of unop * expr
        | Subscript of expr * expr
        | CallExpr of ident * (expr list)
        | Cast of ident * expr

    (** Convert an expression tree to C code. May insert lots of extra parenthesis. *)
    let rec c_of_expr = function
        | Var s                -> sprintf "%s" s
        | StringLit s          -> sprintf "\"%s\"" (String.escaped s)
        | IntLit i             -> string_of_int i
        | EnumLit e            -> e
        | BinExpr (op, e1, e2) -> sprintf "(%s %s %s)" (c_of_expr e1) (c_of_binop op) (c_of_expr e2)
        | UnExpr (op, e)       -> sprintf "(%s %s)" (c_of_unop op) (c_of_expr e)
        | Subscript (e1, e2)   -> sprintf "(%s[%s])" (c_of_expr e1) (c_of_expr e2)
        | CallExpr (f, args)   -> sprintf "%s(%s)" f (String.concat ~sep:", " (List.map ~f:c_of_expr args))
        | Cast (t, e)          -> sprintf "((%s)%s)" t (c_of_expr e)

    (** C statements. We include labels as a statement type because it is convenient. *)
    type statement =
        | Decl of (ident * ident * int option)
        | Assign of (expr * expr)
        | If of (expr * statement * statement option)
        | While of (expr * statement)
        | Return of expr
        | Seq of (statement * statement)
        | Goto of ident
        | Label of ident
        | Expr of expr
        | Skip
        | Comment of string

    (** Convert statements to actual C code in the given
        {!type:Buffer.t}. Uses the {!val:depth} argument to indent
        appropriately. The use of a buffer here is a bit incongrous
        with the previous conversion functions, but greatly reduces
        the amount of string copying needed. *)
    let rec c_of_statement ?depth:(depth = 0) b =
        let indent = (let s = Bytes.create depth in Bytes.fill s ~pos:0 ~len:depth '\t' ; s) in
        let indent = Bytes.to_string indent in
        let depth = depth + 1 in
        function
        | Skip                         -> ()
        | Decl (typ, name, None)       -> bprintf b "%s%s %s;" indent typ name
        | Decl (typ, name, Some count) -> bprintf b "%s%s %s[%d];" indent typ name (count)
        | Assign (lhs, rhs)            -> bprintf b "%s%s = %s;" indent (c_of_expr lhs) (c_of_expr rhs)
        | If (test, th, None)          -> (bprintf b "%sif(%s){\n" indent (c_of_expr test);
                                           c_of_statement b ~depth th;
                                           bprintf b "\n%s}" indent)
        | If (test, th, Some el)       -> (bprintf b "%sif(%s){\n" indent (c_of_expr test);
                                           c_of_statement b ~depth th;
                                           bprintf b "\n%s}else{\n" indent;
                                           c_of_statement b ~depth el;
                                           bprintf b "\n%s}" indent)
        | While (test, body)            -> (bprintf b "%swhile(%s){\n" indent (c_of_expr test);
                                            c_of_statement ~depth:(depth + 1) b body;
                                            bprintf b "\n%s}" indent)
        | Return r                      -> bprintf b "%sreturn (%s);" indent (c_of_expr r)
        | Seq (s1, s2)                  -> (c_of_statement b ~depth:(depth-1) s1;
                                            bprintf b "\n";
                                            c_of_statement b ~depth:(depth-1) s2)
        | Goto label                    -> bprintf b "%sgoto %s;" indent label
        | Label lbl                     -> bprintf b "%s%s:" indent lbl
        | Expr e                        -> bprintf b "%s%s;" indent (c_of_expr e)
        | Comment s                     -> bprintf b "%s//%s" indent s
end

open Primitives


(** A partially build function.

    All function must return integers and will be generated following the form:
    {v
       int name(args...)\{
           /* ... locals ....  */

           /* ... body ... */

           return 0;

           /* cleanups */

       \}
    v}

    Where {i cleanups} is a sled of labels targeted by {i goto}
    statements in the body for error handling.
*)
type pfunc = {
    (** Counter used to generate fresh identifiers *)
    counter : int;
    (** Return type of function *)
    ret_type : ident;
    (** Name of the function *)
    name   : ident; 
    (** Argument list of the function *)
    args   : (ident * ident) list; 
    (** distinguished variable that will be returned. Must be an integer *)
    rcvar  : ident;
    (** variable containing pointer to measurement graph *)
    graphvar : ident; 
    (** variable containing string reperesesnting path to measurement graph *)
    graphpathvar : ident;
    (** variable containing pointer to hash set keeping track of which nodes in the graph are new *)
    node_hashset : ident;
    (** variable containing pointer to mutex *)
    mutex : ident;

    (** List of local variables (type, ident, array cadinality).
            Note: this list is built in reverse order and then reversed
            during code generation *)
    locals : (ident * ident * int option) list;  
    (** List of statements in the body of the function. Like the
            locals, this list is build in reverse and reversed during code
            generation. *) 
    stmts  : statement list; 

    (** Cleanups to be performed on the error handling goto sled. The
            order of the labels is the reverse of the order of the statements
            that need unwinding, so this list is actually build in forwards
            order and doesn't need reversing during code generation. *)
    cleanups : (ident * statement) list 
}

(** An independent C file *)
type cfile = {
    (** list of global includes *)
    includes : ident list;
    (** list of global variable declarations *)
    globals : (ident * ident * int option) list;
    (** list of function definitions *)
    funcs : pfunc list;
}

open State
open Core
(** Get the name of the return variable *)
let get_rcvar : (pfunc, ident, pfunc) t = get >|= fun pf -> pf.rcvar

(** Get the current value of the identifier counter *)
let get_counter : (pfunc, int, pfunc) t = get >|= fun pf -> pf.counter

(** Get the current list of cleanup labels and statements *)
let get_cleanup : (pfunc, (ident * statement) list, pfunc) t = get >|= fun pf -> pf.cleanups

(** Get the identifier of the measurement graph variable *)
let get_graphvar : (pfunc, ident, pfunc) t = get >|= fun pf -> pf.graphvar

(** Get the identifier of the pathname variable of the measurement graph *)
let get_graphpathvar : (pfunc, ident, pfunc) t = get >|= fun pf -> pf.graphpathvar

(** Get the current list of statements *)
let get_stmts : (pfunc, statement list, pfunc) t = get >|= fun pf -> pf.stmts

(** Gets the identifier of the hashset pointer variable *)
let get_node_hashset : (pfunc, ident, pfunc) t = get >|= fun pf -> pf.node_hashset

(** Gets the identifier of the mutex pointer variable *)
let get_mutex : (pfunc, ident, pfunc) t = get >|= fun pf -> pf.mutex

(** Replace the current value of the identifier counter. May cause
    compilation issues if new value < old value. *)
let put_counter i = get >>= fun pf -> put {pf with counter = i}

(** Increment the identifier counter *)
let inc_counter = get_counter >>= fun c -> put_counter (c+1) >|= fun _ -> c

(** Define a new local variable *)
let append_local v = get >>= fun pf -> put {pf with locals = v::pf.locals}

(** Append a new statement to the body of the function *)
let append_statement s = get >>= fun pf -> put {pf with stmts = s::pf.stmts}

(** Prepend a new statement to the body of the function *)
let prepend_statement s = get >>= fun pf -> put {pf with stmts = pf.stmts @ [s]}

(** Merges a list of statements into a single statement *)
let fold_stmt_list (l : statement list) : statement  = List.fold_left ~f:(fun acc stmt -> Seq(acc, stmt)) ~init:Skip l

(** Append the statement {i if e then s1 else s2 } to the body of the function *)
let append_if e s1 s2 =
    append_statement (If(e, fold_stmt_list s1, Option.map ~f:fold_stmt_list s2))

(** Append a commend to the body of the function *)
let append_comment s = 
    append_statement @@ Comment s

(** Prepend a new cleanup statement to the error handling sled. *)
let prepend_cleanup label c = get >>= fun pf -> put {pf with cleanups = (label, c)::pf.cleanups}

(** Generate a fresh {!type:pfunc}. *)
let mkpfunc ?counter:(counter=0) ?ret_type:(ret_type="int") ~name:name ~args:args ~rc:rcvar ~graphvar:graphvar ~graphpathvar:graphpathvar ~node_hashset:node_hashset 
    ?mutex:(mutex = "mutex")
() =
    {
    counter  = counter + 1;
    ret_type = ret_type;
    name     = name;
    args     = args;
    rcvar    = rcvar;
    graphvar = graphvar;
    graphpathvar = graphpathvar;
    node_hashset = node_hashset;
    mutex = mutex;
    locals   = [];
    stmts    = [];
    cleanups = [("return_label_" ^ (string_of_int counter), Return (Var rcvar))]
    }

(** A computation that returns a pfunc that is the same as the current one, 
    except for containing no local variable declarations, statements, or cleanup statements  *)
let mkscope : (pfunc, pfunc, pfunc) State.t =
    let%bind pf = get in
    return {
        pf with
        locals   = [];
        stmts    = [];
        cleanups = [];
    }

(** Generate a fresh identifier by appending {i "_X"} to the given
    string where {i X} is the stringified current value of the identifier
    counter. Increments the identifier counter before returning. *)
let fresh_ident s =
    inc_counter >|=
    fun counter -> sprintf "%s_%d"
                       (String.map ~f:(fun c -> if (Char.is_alpha c || Char.is_digit c || Char.equal c '_')
                                          then c else '_') s)
                       counter

(** Given the identifier of a pipe variable, return an expression for
    accessing its read end (i.e., {i ident[0]}). *)
let pipe_read_end_expr ident = (Subscript (Var ident, IntLit 0))
(** Given the identifier of a pipe variable, return an expression for
    accessing its write end (i.e., {i ident[1]}). *)
let pipe_write_end_expr ident = (Subscript (Var ident, IntLit 1))

(** Returns a statement that jumps to the corresponding cleanup code block *)
let goto_next_cleanup : (pfunc, statement, pfunc) t = 
    let%bind cleanups = get_cleanup in 
    match cleanups with
    | [] -> return Skip (*replace with goto the return stmt*)
    | (label, _ ) :: _ -> return @@ Goto label

(** Returns a list of statements consisting of the core statements followed by labelled cleanup blocks *)
let append_cleanups_to_stmts (stmts : statement list) (cleanups : (ident * statement) list) =
    let cleanup_stmts = List.map ~f:(fun (label, stmt) -> Seq(Label label, stmt)) cleanups in
    stmts @ cleanup_stmts

(** Appends cleanup blocks to core stmts and clears cleanups *)
let register_cleanups : (pfunc, unit, pfunc) t =
    fun pf -> ((), 
    {
        pf with 
        stmts = append_cleanups_to_stmts pf.stmts pf.cleanups; 
        cleanups = []
    })

 (** Generate a single statement from the given {!type:pfunc} that
     includes the local variable declarations, body statements, and
     cleanups. This is used to inline the body of one {!type:pfunc}
     into a block in another {!type:pfunc}. *)
let stmt_of_pf pf =
    let decls = List.rev_map ~f:(fun local -> Decl local) pf.locals in
    let stmts = List.rev pf.stmts in
    let cleanups = List.map ~f:(fun (label, stmt) -> Seq(Label label, stmt)) pf.cleanups in
    Seq (fold_stmt_list decls, (Seq(fold_stmt_list stmts, fold_stmt_list cleanups)))


(** Takes a stateful computation that produces code, 
    and uses it to create a statement containing the body of that code
    that can be used in a different stateful computation context *)
let stmt_of_comp (c : (pfunc, 'a, pfunc) State.t) :
(pfunc,'a * statement, pfunc) State.t =
    let%bind counter = get_counter in
    let%bind rcvar   = get_rcvar in
    let%bind graphvar = get_graphvar in
    let%bind graphpathvar = get_graphpathvar in
    let%bind node_hashset = get_node_hashset in
    let (x, pf) = run c (mkpfunc ~name:"ignored" ~args:[] ~rc:rcvar ~graphvar:graphvar ~graphpathvar:graphpathvar ~counter:counter ~node_hashset:node_hashset ()) in
    let%bind _ = put_counter pf.counter in
    return (x, stmt_of_pf pf)
    

(** Takes a stateful computation that produces code, 
    and uses it to create a statement containing the body of that code
    that can be used in a different stateful computation context *)
let stmt_of_comp_scope (c : (pfunc, 'a, pfunc) State.t) :
(pfunc,'a * statement, pfunc) State.t =
    let%bind pf1 = mkscope in
    let (x, pf2) = run c pf1 in
    let%bind _   = put_counter pf2.counter in
    return (x, stmt_of_pf pf2)

(** Appends a while loop to the generated code *)
let append_while (b : expr) (s : statement) : (pfunc, unit, pfunc) State.t =
    append_statement @@ While (b, s)


(** Convert the {!type:pfunc} to a self contained compilable C
file and print that file to a buffer. Includes generation of necessary {i #include} directives for
functions used by the generators in this module, and {i extern}
declarations for the quasi-builtins. *)
let print_pfunc_to_buffer pf b =
    let args_string = 
        let arg_to_string (typ, ident) = typ^" "^ident in
        String.concat ~sep:", " (List.map ~f:arg_to_string pf.args) in
    bprintf b "%s %s(%s){\n" pf.ret_type pf.name args_string;
    List.iter ~f:(fun local ->
        c_of_statement ~depth:1 b (Decl local);
        Buffer.add_char b '\n')
        (("int", pf.rcvar, None)::
        (List.rev pf.locals));
    List.iter ~f:(fun stmt ->
        c_of_statement ~depth:1 b stmt;
        Buffer.add_char b '\n')
        (List.rev pf.stmts);
    List.iter ~f:(fun (label, cleanup) ->
        c_of_statement ~depth:0 b (Label label);
        Buffer.add_char b '\n';
        c_of_statement ~depth:1 b cleanup;
        Buffer.add_char b '\n')
        pf.cleanups;
    bprintf b "\n}"



(** Print a {!type:cfile} to a buffer *)
let print_cfile_to_buffer cf b =
    List.iter cf.includes ~f:(fun incl -> bprintf b "#include %s\n" incl);
    List.iter ~f:(fun global -> 
        c_of_statement ~depth:0 b (Decl global);
        Buffer.add_char b '\n';
        ) (List.rev cf.globals);
    List.iter ~f:(fun pf -> print_pfunc_to_buffer pf b) cf.funcs

(** Print a {!type:cfile}  *)
let cfile_to_string cf = 
    let b = Buffer.create 1024 in
    print_cfile_to_buffer  cf b;
    Buffer.contents b