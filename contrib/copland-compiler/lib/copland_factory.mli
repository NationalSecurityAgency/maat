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

(** Create an AST representation of a USM command. Corresponds to an ASP call. *)
val make_usm : string -> string -> string list -> Copland.workflow

(** Create an AST representation of an AT command. Corresponds to remotely running a copland phrase *)
val make_at : string -> Copland.workflow -> Copland.workflow

(** Create an AST representation of a SIG command. Corresponds to signing the measurement graph. *)
val make_sig : Copland.workflow

(** Create an AST representation of an arrow Command. Corresponds to sequentially executing copland phrases, sending the output of one to the next *)
val make_arrow : Copland.workflow -> Copland.workflow -> Copland.workflow

(** Create an AST representation of sequential branching command. Corresponds to sequentially executing copland phrases, given the same input. *)
val make_seq_branch : Copland.workflow -> Copland.workflow -> Copland.workflow

(** Create an AST representation of a concurrent branching command. Corresponds to running two copland phrases concurrently. *)
val make_conc_branch : Copland.workflow -> Copland.workflow -> Copland.workflow