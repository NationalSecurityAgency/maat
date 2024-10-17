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

(** Information needed to compile an ASP that can be found in an ASP's xml file *)
type asp_t = {
  asp_name : string;
  uuid : string;
  target_type : string;
  address_type : string;
  measurement_type : string option;
}

exception AspNotFound of string

(** A mutable reference pointing to the directory containing asp source code *)
val asps_dir : string ref

(** Generates an asp_t corresponding to [asp_name] provided such an asp is
    defined *)
val get_asp : string -> asp_t
