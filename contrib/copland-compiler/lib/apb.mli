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

(** Generate a call to {i waitpid} for the given PID expression.

    Adds a local variable for the child status, appends the {i waitpid} call and
    discards the return value.

    Returns the expression for the child status variable. *)
val make_waitpid_pf :
  Ccode.Primitives.expr ->
  (Ccode.pfunc, Ccode.Primitives.expr, Ccode.pfunc) State.t

(** Generates code to initialize the measurement graph Returns variables
    representing the measurement graph pointer and a pointer to the path
    pointing to the measurement graph *)
val init_meas_graph :
  ( Ccode.pfunc,
    Ccode.Primitives.expr * Ccode.Primitives.expr,
    Ccode.pfunc )
  State.t

(** Generates code to call a function that implements signing and sending the
    current measurment graph *)
val sign_meas : (Ccode.pfunc, Ccode.Primitives.expr, Ccode.pfunc) State.t

(** Takes a computation that generates code, uses it to create a statement
    containing the body of the code, and runs it asynchronously. Returns the
    process id of the child process. *)
val async_run :
  (Ccode.pfunc, 'a, Ccode.pfunc) State.t ->
  (Ccode.pfunc, Ccode.Primitives.expr, Ccode.pfunc) State.t

(** Takes a computation that generates code and returns an expression (possibly
    limitted by the scope of the computation), uses it to create a statement
    containing the body of the code, appends a command to assign the result
    expression to a variable declared in the outer scope, and runs it
    asynchronously. Returns the process id of the child process and the variable
    that stores the result. Note that the variable will not actually hold the
    intended computation until after the child process has terminated. *)
val async_run_ret :
  Ccode.Primitives.ident ->
  (Ccode.pfunc, Ccode.Primitives.expr option, Ccode.pfunc) State.t ->
  ( Ccode.pfunc,
    Ccode.Primitives.expr * Ccode.Primitives.expr option,
    Ccode.pfunc )
  State.t

(** List of includes required for apb file *)
val standard_apb_includes : string list

(** Convert the {!type:pfunc} to a self contained compilable C file. Includes
    generation of necessary {i #include} directives for functions used by the
    generators in this module, and {i extern} declarations for the
    quasi-builtins. *)
val c_of_pfunc : Ccode.pfunc -> string

(** Generate code to find a specific ASP in a set of ASPs

    Defines a new local variable which holds the reference to the ASP, adds body
    statement in the case of an error, and a label to jump to if an error
    occurs.

    Returns the identifier for the ASP *)
val find_asp :
  string -> (Ccode.pfunc, Ccode.Primitives.expr, Ccode.pfunc) State.t

(** Generates code that produces an expression containing the node id of a file
    argument to an asp. If the file does not already have a corresponding node
    in the measurement with the corresponding target type, the code will
    initialize one. *)
val get_node_id_str :
  Asp.asp_t ->
  Ccode.Primitives.expr ->
  (Ccode.pfunc, Ccode.Primitives.expr, Ccode.pfunc) State.t

(** Transforms special asp argument expression, graph, into corresponding
    asp_measure function arguement *)
val handle_special_arg :
  Ccode.Primitives.expr ->
  (Ccode.pfunc, Ccode.Primitives.expr option, Ccode.pfunc) State.t
