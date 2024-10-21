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
    functions implementing workflows using the {!module:State} monad. *)

module Primitives : sig
  type ident = string

  (** Binary operators in C *)
  type binop =
    | Add
    | Sub
    | Mul
    | Div
    | Mod
    | Land
    | Lor
    | Band
    | Bor
    | Bxor
    | Lt
    | Le
    | Neq
    | Eq
    | Gt
    | Ge
    | Deref

  val c_of_binop : binop -> string
  (** Convert a binop to the infix C operator (e.g., [c_of_binop Add = "+"]). *)

  (** Unary operators in C *)
  type unop = AddrOf | PointsTo | Neg | Lnot | Bnot

  val c_of_unop : unop -> string
  (** Convert a unary operator to the prefix C operator (e.g., [c_of_unop AddrOf = "&"]). *)

  (** C style expressions. *)
  type expr =
    | Var of ident
    | StringLit of ident
    | IntLit of int
    | EnumLit of ident
    | BinExpr of binop * expr * expr
    | UnExpr of unop * expr
    | Subscript of expr * expr
    | CallExpr of ident * expr list
    | Cast of ident * expr

  val c_of_expr : expr -> string
  (** Convert an expression tree to C code. May insert lots of extra parenthesis. *)

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
    | Comment of ident

  val c_of_statement : ?depth:int -> Buffer.t -> statement -> unit
  (** Convert statements to actual C code in the given
      {!type:Buffer.t}. Uses the {!val:depth} argument to indent
      appropriately. The use of a buffer here is a bit incongrous
      with the previous conversion functions, but greatly reduces
      the amount of string copying needed. *)
end

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
    ret_type : string;
    (** Name of the function *)
    name   : string; 
    (** Argument list of the function *)
    args   : (string * string) list; 
    (** distinguished variable that will be returned. Must be an integer *)
    rcvar  : string;
    (** variable containing pointer to measurement graph *)
    graphvar : string; 
    (** variable containing string reperesesnting path to measurement graph *)
    graphpathvar : string;
    (** variable containing pointer to hash set keeping track of which nodes in the graph are new *)
    node_hashset : string;
    (** variable containing pointer to mutex *)
    mutex : string;

    (** List of local variables (type, ident, array cadinality).
            Note: this list is built in reverse order and then reversed
            during code generation *)
    locals : (string * string * int option) list;  
    (** List of statements in the body of the function. Like the
            locals, this list is build in reverse and reversed during code
            generation. *) 
    stmts  : Primitives.statement list; 

    (** Cleanups to be performed on the error handling goto sled. The
            order of the labels is the reverse of the order of the statements
            that need unwinding, so this list is actually build in forwards
            order and doesn't need reversing during code generation. *)
    cleanups : (string * Primitives.statement) list 
}

(** An independent C file *)
type cfile = {
    (** list of global includes *)
    includes : string list;
    (** list of global variable declarations *)
    globals : (string * string * int option) list;
    (** list of function definitions *)
    funcs : pfunc list;
}

(** Get the name of the return variable *)
val get_rcvar : (pfunc, Primitives.ident, pfunc) State.t

(** Get the current value of the identifier counter *)
val get_counter : (pfunc, int, pfunc) State.t

(** Get the current list of cleanup labels and statements *)
val get_cleanup :
  (pfunc, (Primitives.ident * Primitives.statement) list, pfunc) State.t

(** Get the identifier of the measurement graph variable *)
val get_graphvar : (pfunc, Primitives.ident, pfunc) State.t

(** Get the identifier of the pathname variable of the measurement graph *)
val get_graphpathvar : (pfunc, Primitives.ident, pfunc) State.t

(** Gets the identifier of the hashset pointer variable *)
val get_node_hashset : (pfunc, Primitives.ident, pfunc) State.t

(** Get the current list of statements *)
val get_stmts : (pfunc, Primitives.statement list, pfunc) State.t

(** Gets the identifier of the mutex pointer variable *)
val get_mutex : (pfunc, Primitives.ident, pfunc) State.t

(** Replace the current value of the identifier counter.
    Assumes that the new value is >= the old value . *)
val put_counter : int -> (pfunc, unit, pfunc) State.t

(** Increment the identifier counter *)
val inc_counter : (pfunc, int, pfunc) State.t

(** Define a new local variable *)
val append_local :
  Primitives.ident * Primitives.ident * int option ->
  (pfunc, unit, pfunc) State.t

(** Append a new statement to the body of the function *)
val append_statement : Primitives.statement -> (pfunc, unit, pfunc) State.t

(** Prepend a new statement to the body of the function *)
val prepend_statement : Primitives.statement -> (pfunc, unit, pfunc) State.t

(** Append the statement {i if e then s1 else s2 } to the body of the function *)
val append_if :
  Primitives.expr ->
  Primitives.statement list ->
  Primitives.statement list option ->
  (pfunc, unit, pfunc) State.t

(** Prepend a new cleanup statement to the error handling sled. *)
val append_comment : string -> (pfunc, unit, pfunc) State.t

(** Prepend a new cleanup statement to the error handling sled. *)
val prepend_cleanup :
  Primitives.ident -> Primitives.statement -> (pfunc, unit, pfunc) State.t

(** Generate a fresh {!type:pfunc}. *)
val mkpfunc :
  ?counter:int ->
  ?ret_type:string ->
  name:Primitives.ident ->
  args:(Primitives.ident * Primitives.ident) list ->
  rc:Primitives.ident ->
  graphvar:Primitives.ident ->
  graphpathvar:Primitives.ident ->
  node_hashset:Primitives.ident ->
  ?mutex :Primitives.ident ->
  unit ->
  pfunc

(** Generate a fresh identifier by appending {i "_X"} to the given
    string where {i X} is the stringified current value of the identifier
    counter. Increments the identifier counter before returning. *)
val fresh_ident : string -> (pfunc, string, pfunc) State.t

(** Given the identifier of a pipe variable, return an expression for
    accessing its read end (i.e., {i ident[0]}). *)
val pipe_read_end_expr : Primitives.ident -> Primitives.expr

(** Given the identifier of a pipe variable, return an expression for
    accessing its write end (i.e., {i ident[1]}). *)
val pipe_write_end_expr : Primitives.ident -> Primitives.expr

(** Returns a statement that jumps to the corresponding cleanup code block *)
val goto_next_cleanup : (pfunc, Primitives.statement, pfunc) State.t

(** Returns a list of statements consisting of the core statements followed by labelled cleanup blocks *)
val append_cleanups_to_stmts :
  Primitives.statement list ->
  (Primitives.ident * Primitives.statement) list ->
  Primitives.statement list

(** Appends cleanup blocks to core stmts and clears cleanups *)
val register_cleanups : (pfunc, unit, pfunc) State.t

(** Merges a list of statements into a single statement *)
val fold_stmt_list : Primitives.statement list -> Primitives.statement

(** Generate a single statement from the given {!type:pfunc} that
    includes the local variable declarations, body statements, and
    cleanups. This is used to inline the body of one {!type:pfunc}
    into a block in another {!type:pfunc}. *)
val stmt_of_pf : pfunc -> Primitives.statement

(** Takes a stateful computation that produces code, 
    and uses it to create a statement containing the body of that code
    that can be used in a different stateful computation context *)
val stmt_of_comp : (pfunc, 'a, pfunc) State.t -> (pfunc,'a * Primitives.statement, pfunc) State.t

(** Takes a stateful computation that produces code, 
    and uses it to create a statement containing the body of that code
    that can be used in a different stateful computation context *)
val stmt_of_comp_scope : (pfunc, 'a, pfunc) State.t -> (pfunc,'a * Primitives.statement, pfunc) State.t

(** Print a {!type:cfile} to a buffer *)
val print_cfile_to_buffer : cfile -> Buffer.t -> unit

(** Print a {!type:cfile}  *)
val cfile_to_string : cfile -> string

(** Appends a while loop to the generated code *)
val append_while : Primitives.expr -> Primitives.statement -> (pfunc, unit, pfunc) State.t

(** A computation that returns a pfunc that is the same as the current one, 
    except for containing no local variable declarations, statements, or cleanup statements  *)
val mkscope : (pfunc, pfunc, pfunc) State.t