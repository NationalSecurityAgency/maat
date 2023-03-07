(**
 * Copyright 2023 United States Government
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

open Printf;;
open Core;;

(** Basic C syntax types *)
module Primitives = struct
    type ident = string;; (** C identifiers *)

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

    (** C statements. We include labels as a statement type because it is convenient. *)
    type statement =
        | Decl of (ident * ident * int option)
        | Assign of (ident * expr)
        | If of (expr * statement * statement option)
        | While of (expr * statement)
        | Return of expr
        | Seq of (statement * statement)
        | Goto of ident
        | Label of ident
        | Expr of expr
        | Skip

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
        | Decl (typ, name, Some count) -> bprintf b "%s%s %s[%d];" indent typ name count
        | Assign (lhs, rhs)            -> bprintf b "%s%s = %s;" indent lhs (c_of_expr rhs)
        | If (test, th, None)          -> (bprintf b "%sif(%s){\n" indent (c_of_expr test);
                                           c_of_statement b ~depth th;
                                           bprintf b "\n%s}" indent)
        | If (test, th, Some el)       -> (bprintf b "%sif(%s){\n" indent (c_of_expr test);
                                           c_of_statement b ~depth th;
                                           bprintf b "\n%s}else{\n" indent;
                                           c_of_statement b ~depth el;
                                           bprintf b "\n%s}" indent)
        | While (test, body)            -> (bprintf b "%swhile(%s){\n" indent (c_of_expr test);
                                            c_of_statement b body;
                                            bprintf b "\n%s}" indent)
        | Return r                      -> bprintf b "%sreturn (%s);" indent (c_of_expr r)
        | Seq (s1, s2)                  -> (c_of_statement b ~depth:(depth-1) s1;
                                            bprintf b "\n";
                                            c_of_statement b ~depth:(depth-1) s2)
        | Goto label                    -> bprintf b "%sgoto %s;" indent label
        | Label lbl                     -> bprintf b "  %s:" lbl
        | Expr e                        -> bprintf b "%s%s;" indent (c_of_expr e)
end

open Primitives;;

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
    counter : int;  (** Counter used to generate fresh identifiers *)
    name   : ident; (** Name of the funciton *)
    args   : (ident * ident) list; (** Argument list of the function *)
    rcvar  : string; (** distinguished variable that will be returned. Must be an integer *)

    locals : (ident * ident *int option) list;  (** List of local variables (type, ident, array cadinality).
                                                    Note: this list is built in reverse order and then reversed
                                                    during code generation *)

    stmts  : statement list; (** List of statements in the body of the function. Like the
                                 locals, this list is build in reverse and reversed during code
                                 generation. *)

    cleanups : statement list (** Cleanups to be performed on the error handling goto sled. The
                                  order of the labels is the reverse of the order of the statements
                                  that need unwinding, so this list is actually build in forwards
                                  order and doesn't need reversing during code generation. *)
}

open State;;

(** Get the name of the return variable *)
let get_rcvar = get >|= fun pf -> pf.rcvar

(** Get the current value of the identifier counter *)
let get_counter = get >|= fun pf -> pf.counter

(** Replace the current value of the identifier counter. May cause
    compilation issues if new value < old value. *)
let put_counter i = get >>= fun pf -> put {pf with counter = i}

(** Increment the identifier counter *)
let inc_counter = get_counter >>= fun c -> put_counter (c+1) >|= fun _ -> c

(** Define a new local variable *)
let append_local v = get >>= fun pf -> put {pf with locals = v::pf.locals}

(** Append a new statement to the body of the function *)
let append_statement s = get >>= fun pf -> put {pf with stmts = s::pf.stmts}

(** Prepend a new cleanup statement to the error handling sled. *)
let prepend_cleanup c = get >>= fun pf -> put {pf with cleanups = c::pf.cleanups}

(** Generate a fresh {!type:pfunc}. *)
let mkpfunc ?counter:(counter=0) ~name:name ~args:args ~rc:rcvar () =
    {counter  = counter;
     name     = name;
     args     = args;
     rcvar    = rcvar;
     locals   = [];
     stmts    = [];
     cleanups = []}

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

(** Generate code to open a fresh pipe with identifier based on the
    given string.

    Defines a new local variable for the pipe, adds body
    statements to open the pipe and check for error, and adds cleanups
    to close the pipe if an error occurs later.

    Returns the pair of expression {i(read end, write end)} for later
    use.
*)
let make_pipe_pf pipename =
    let%bind pipeident = fresh_ident pipename in
    let%bind outlabel  = fresh_ident ("out_"^pipename) in
    let%bind rcvar     = get_rcvar in
    let%bind _         = append_local ("int", pipeident, Some 2) in
    let%bind _         = append_statement (Seq (Assign (rcvar, CallExpr ("pipe", [Var pipeident])),
                                                If (BinExpr (Neq, Var rcvar, IntLit 0),
                                                    Seq (Expr (CallExpr ("dlog", [IntLit 0;
                                                                                  StringLit "Failed to create pipe: %s\n";
                                                                                  CallExpr ("strerror", [Var "errno"])])),
                                                         Goto outlabel),
                                                    None
                                                   )
                                               )
                                          ) in
    let%map _         = prepend_cleanup (Seq
                                             (Seq (Expr (CallExpr ("close", [Subscript (Var pipeident, IntLit 0)])),
                                                   Expr (CallExpr ("close", [Subscript (Var pipeident, IntLit 1)]))),
                                              Label outlabel)) in
    (pipe_read_end_expr pipeident, pipe_write_end_expr pipeident)

(** Generate code to process the target and the argument vector

    This function permits the development of "special" targets which
    have meaning within Copland. As an example, a target of "peerchan"
    could be used to refer to the peerchannel as the target of an
    invocation of run_asp.

    Returns a vector of the arguments with the target  *)
let handle_target target argv outfd =
    match target,argv with
    | "",[]                -> ([EnumLit "NULL"], outfd)
    | "peerchan",[]        -> ([EnumLit "NULL"], Var (ident "peerchan"))
    | "resultschan",[]     -> ([EnumLit "NULL"], Var (ident "resultschan"))
    | "peerchan",(_::_)    -> (argv, Var (ident "peerchan"))
    | "resultschan",(_::_) -> (argv, Var (ident "resultschan"))
    | _,_                  -> ((StringLit target)::argv, outfd)

exception InvalidArray of string

(** Generate code to assign all of the elements contained in the array elements to the
    array whose variable name is given in arr starting at the index given at index.

    Returns a C expression variable of the array name in order to make the compiler happy *)
let rec assign_array arr elements index =
    match elements with
    | [] -> raise (InvalidArray "Do not provide this function an empty list")
    | (h::[]) -> let%map _ = append_statement (Assign (arr^"["^(string_of_int index)^"]", h)) in
                             Var arr
    | (h::r) -> let%bind _ = append_statement (Assign (arr^"["^(string_of_int index)^"]", h)) in
                              assign_array arr r (index + 1)

(** Generate code to declare an argv for use by run_asp.

    Defines a new local variable which holds the arguments to the ASP,
    and adds a new body statement which assigns the required variables
    into the array

    Returns the variable name of the array *)
let declare_argv_array (ident : string) (elements : expr list) =
    match List.length elements with
    |0 -> let%map null = return (EnumLit "NULL") in null
    |num -> let%bind arrident = fresh_ident (ident^"_argv") in
            let%bind _        = append_local ("char *", arrident, Some (num)) in
            let%map _         = assign_array arrident elements 0 in
            Var arrident

(** Generate code to find a specific ASP in a set of ASPs

    Defines a new local variable which holds the reference to the ASP,
    adds body statement in the case of an error, and a label to jump to
    if an error occurs.

    Returns the identifier for the ASP *)
let find_asp asp =
    let%bind rcvar    = get_rcvar in
    let%bind varident = fresh_ident (asp^"_asp") in
    let%bind outlabel = fresh_ident ("find_"^asp^"_error") in
    let%bind _        = append_local ("struct asp", "*"^varident, None) in
    let%bind _        = append_statement (Seq (Assign (varident, CallExpr ("find_asp", [BinExpr (Deref, Var "apb", Var "asps");
                                                                                        StringLit asp])),
                                               If (BinExpr (Eq, Var varident, EnumLit "NULL"),
                                                   Seq (Expr (CallExpr ("dlog", [IntLit 0;
                                                                                 StringLit "Failed to find ASP: %s\n";
                                                                                 BinExpr (Deref, Var varident, Var "name")])),
                                                        Seq (Assign (rcvar, IntLit 1),
                                                             Goto outlabel)),
                                                   None
                                                  )
                                               )
                                         ) in
    let%map _         = prepend_cleanup (Label outlabel) in
    Var varident

(** Generate code to call the {i runasp()} quasi-builtin.

    Adds the call to {i runasp()} and error handling code,
    and adds a cleanup to {i kill()} the child.

    Returns the identifier for the pid of the child.

    ASP execution is asynchronous by default, might be good to
    explore allowing this to vary
*)
let make_runasp_pf close_us infd outfd asp target argv =
    let%bind asp_var   = find_asp asp in
    let (av, ofd)      = handle_target target argv outfd in
    let%bind rcvar     = get_rcvar in
    let%bind outlabel  = fresh_ident (asp^"_pid_label") in
    let%bind argvident = declare_argv_array asp av in
    let%bind varident  = fresh_ident (asp^"_pid") in
    let%bind _         = append_local ("pid_t", varident, None) in
    let%bind _         = append_statement (Seq (Assign (varident, CallExpr ("run_asp", [asp_var; infd; ofd]@
                                                                                       [EnumLit "true"]@
                                                                                       [IntLit (List.length av); argvident]@
                                                                                       close_us)),
                                                If (BinExpr (Lt, Var varident, IntLit 0),
                                                    Seq (Expr (CallExpr ("dlog", [IntLit 0;
                                                                                  StringLit (sprintf "Failed to run asp \"%s\"\n" asp);
                                                                      ])),
                                                         Seq (Assign (rcvar, Var varident),
                                                              Goto outlabel)),
                                                    None))) in
    let%map _          = prepend_cleanup (Seq (Expr (CallExpr ("kill", [Var varident; EnumLit "SIGKILL"])),
                                             Label outlabel)) in
    Var rcvar

(** Generate code to call the {i fork_and_buffer()} quasi-builtin.

    Defines new local variables for the pid of the child and the read
    end of the pipe created by {i fork_and_buffer}, adds the call and
    error handling, and adds a cleanup to kill the child and close the
    pipe.

    Returns the pair of expressions {i (child pid, read fd)}.
*)
let make_fork_and_buffer_pf infd close_us =
    let%bind pidident    = fresh_ident "buffer_pid" in
    let%bind bufpiperead = fresh_ident "buffer_pipe_readend" in
    let%bind outlabel    = fresh_ident "out_runbuffer" in
    let%bind rcvar       = get_rcvar in
    let%bind _           = append_local ("int", bufpiperead, None) in
    let%bind _           = append_local ("pid_t", pidident, None) in
    let%bind _           = append_statement (Seq (Assign (rcvar, CallExpr ("fork_and_buffer", (UnExpr (AddrOf, (Var pidident)))::
                                                                                                 (UnExpr (AddrOf, (Var bufpiperead)))::
                                                                                                 infd::close_us@[IntLit (-1)])),
                                                  If (BinExpr (Lt, Var rcvar, IntLit 0),
                                                      Seq (Expr (CallExpr ("dlog", [IntLit 0;
                                                                                    StringLit "Failed to fork buffering process: %s\n";
                                                                                    CallExpr ("strerror", [Var "errno"])])),
                                                           Goto outlabel),
                                                      None))) in
    let%map _            = prepend_cleanup (Seq
                                                (Seq (Expr (CallExpr ("kill", [Var pidident; EnumLit "SIGKILL"])),
                                                      Expr (CallExpr ("close", [Var bufpiperead]))),
                                                 Label outlabel)) in
    (Var pidident, Var bufpiperead)

(** Generate a call to {i open()}.

    Defines a new local variable for the file descriptor, adds the
    call statements and error checking, and adds a cleanup to close
    the descriptor.

    Returns the expression for the newly opened descriptor.
*)
let make_open_pf name path flags =
    let%bind fdident  = fresh_ident name in
    let%bind outlabel = fresh_ident ("out_open_"^name)  in
    let%bind rcvar    = get_rcvar in
    let%bind _        = append_local ("int", fdident, None) in
    let%bind _        = append_statement (Seq (Assign (fdident, CallExpr ("open", [path; flags])),
                                               If (BinExpr (Lt, (Var fdident), (IntLit 0)),
                                                   Seq (Expr (CallExpr ("dlog", [IntLit 0;
                                                                                 StringLit "Failed to open file \"%s\": %s\n";
                                                                                 path;
                                                                                 CallExpr ("strerror", [Var "errno"])])),
                                                        Seq (Assign (rcvar, Var fdident),
                                                             Goto outlabel)),
                                                   None))) in
    let%map _         = prepend_cleanup (Seq (Expr (CallExpr ("close", [Var fdident])),
                                              Label outlabel)) in
    Var fdident

(** Generate a call to close the given file descriptor.

    Just adds a call to {i close()} to the body of the function.
*)
let make_close_pf fdexpr =
    append_statement (Expr (CallExpr ("close", [fdexpr])))

(** Generate a call to {i waitpid} for the given PID expression.

    Adds a local variable for the child status, appends the {i
    waitpid} call and discards the return value.

    Returns the expression for the child status variable.
*)
let make_waitpid_pf pidexpr =
    let%bind statusvar = fresh_ident "status" in
    let%bind _         = append_local ("int", statusvar, None) in
    let%map _          = append_statement (Expr (CallExpr ("waitpid", [pidexpr;
                                                                       UnExpr (AddrOf, Var statusvar);
                                                                       IntLit 0]))) in
    Var statusvar

(** Convert an expression of {i int} type to a string in a fixed size
    stack buffer of length 12 (maximum length of a 4-byte int is sign flag
    + 10 digits + '\0' ).

    Adds a new local variable for the stack buffer, and appends a call
    to {i snprintf}. Does no error checking.

    Returns the expression for the string buffer variable identifier.
*)
let make_string_of_int intexpr =
    let%bind strvar = fresh_ident "string_of_int" in
    let%bind _      = append_local ("char", strvar, Some 12) in
    let%map  _      = append_statement (Expr (CallExpr ("snprintf",
                                                        [Var strvar;
                                                         IntLit 12;
                                                         StringLit "%d";
                                                         intexpr]))) in
    Var strvar

(** Convert the {!type:pfunc} to a self contained compilable C
    file. Includes generation of necessary {i #include} directives for
    functions used by the generators in this module, and {i extern}
    declarations for the quasi-builtins. *)
let c_of_pfunc pf =
    let b = Buffer.create 1024 in
    bprintf b "#include <stdio.h>\n";
    bprintf b "#include <sys/types.h>\n";
    bprintf b "#include <sys/wait.h>\n";
    bprintf b "#include <unistd.h>\n";
    bprintf b "#include <fcntl.h>\n";
    bprintf b "#include <errno.h>\n";
    bprintf b "#include <string.h>\n";
    bprintf b "#include <signal.h>\n";
    bprintf b "#include <common/apb_info.h>\n";
    bprintf b "#include <maat-basetypes.h>\n";
    bprintf b "#include <util/util.h>\n";
    bprintf b "#include <common/asp.h>\n";
    bprintf b "#include <maat-envvars.h>\n";
    bprintf b "#include <apb/apb.h>\n";
    bprintf b "#include \"apb-common.h\"\n\n";

    bprintf b "int %s(%s){\n"
        pf.name (String.concat ~sep:", "
                     (List.map ~f:(fun (typ,ident) ->
                                       typ^" "^ident)
                           pf.args));
    List.iter ~f:(fun local ->
                     c_of_statement ~depth:1 b (Decl local);
                     Buffer.add_char b '\n')
        (("int", pf.rcvar, None)::
         (List.rev pf.locals)) ;
    List.iter ~f:(fun stmt ->
                     c_of_statement ~depth:1 b stmt;
                     Buffer.add_char b '\n')
        (List.rev pf.stmts) ;
    List.iter ~f:(fun cleanup ->
                     c_of_statement ~depth:1 b cleanup;
                     Buffer.add_char b '\n')
        pf.cleanups;
    c_of_statement b ~depth:1 (Return (Var pf.rcvar));
    bprintf b "\n}";
    Buffer.contents b

(** Generate a single statement from the given {!type:pfunc} that
    includes the local variable declarations, body statements, and
    cleanups. This is used to inline the body of one {!type:pfunc}
    into a block in another {!type:pfunc}. *)
let stmt_of_pf pf =
    List.fold_left ~f:(fun stmt -> fun cleanup -> Seq (stmt, cleanup))
        ~init:(List.fold_left ~f:(fun stmt -> fun bodypart -> Seq (stmt, bodypart))
                   ~init:(List.fold_left ~f:(fun stmt -> fun local -> Seq (stmt, (Decl local)))
                              ~init:Skip (List.rev pf.locals))
                   (List.rev pf.stmts))
        pf.cleanups
