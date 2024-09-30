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

(** Used by {!const:workflow.LIN} and {!const:workflow.BRNCH} to control the
    synchronization of subflows. {!const:exec_flow.CONC} denotes concurrent
    execution, {!const:exec_flow.SEQ} denotes sequential. *)
type exec_flow = CONC | SEQ

(** The workflow type is at the heart of everything and is intended to vaguely
    resemble the structure of Copland terms. The four constructors should be
    interpreted as follows:
    - {!const:workflow.PRIM}: just runs a command with a target and command line
      arguments (Primitive)
    - {!const:workflow.LIN}: run two workflows with the output of the first sent
      to the input of the second (Linear)
    - {!const:workflow.BRNCH}: run two workflows in with the same input and merging their outputs,
      an {!type:exec_flow} determines if they are run sequentially or concurrently *)
type workflow =
  | SIG
  | PRIM of atomic_flow
  | LIN of exec_flow * linear_flow
  | BRNCH of exec_flow * branching_flow
  | AT of string * workflow

and atomic_flow = { cmd : string; target : string; args : string list }
and linear_flow = { first : workflow; second : workflow }

and branching_flow = {
  left : workflow;
  right : workflow;
}