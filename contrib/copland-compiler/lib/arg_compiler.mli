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

open Util
open Copland
open Ccode
open Primitives

(** A computation that produces code implemented a Copland workflow with
    specified arguments.
    @param args
      A map that specifies the argument batches for the copland workflow
    @param wf The Copland workflow that is being compiled
    @param input_queue
      an expr option option that represents a possibly present queue
      representing new nodes created by the previous Copland phrase. Some (Some
      q) represents the case where the previous phrase providing an expr
      containing a pointer to such a q. Some None represents the case where the
      previous phrase produced new nodes but the queue has not yet been computed
      (this is necessary for dealing with asynchronous phrases). None represents
      the case where the prevous phrase cannot have produced any new nodes.
    @return
      A list of process ids representing asynchronous processes spawned by this
      computation and an expr option option representing possibly present queue
      of new nodes. *)
val compile_wf :
  arg_map ->
  workflow ->
  expr option option ->
  (pfunc, expr list * expr option option, pfunc) State.t

(** Produces a string containing the body of a C file implementing a Copland
    workflow with specified arguements Relies on the compile_wf function and
    provides a context for the code produced by compile_wf to run. *)
val compile : arg_map -> workflow -> string
