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

open Copland

(** Create an AST representation of a USM command. Corresponds to an ASP call. *)
let make_usm cmd target args = PRIM { cmd; target; args }

(** Create an AST representation of an AT command. Corresponds to remotely running a copland phrase *)
let make_at loc wf = AT (loc, wf)

(** Create an AST representation of a SIG command. Corresponds to signing the measurement graph. *)
let make_sig = SIG

(** Create an AST representation of an arrow Command. Corresponds to sequentially executing copland phrases, sending the output of one to the next *)
let make_arrow wf1 wf2 = LIN (SEQ, { first = wf1; second = wf2 })

(** Create an AST representation of sequential branching command. Corresponds to sequentially executing copland phrases, given the same input. *)
let make_seq_branch wf1 wf2 = BRNCH (SEQ, { left = wf1; right = wf2 })

(** Create an AST representation of a concurrent branching command. Corresponds to running two copland phrases concurrently. *)
let make_conc_branch wf1 wf2 = BRNCH (CONC, { left = wf1; right = wf2 })
