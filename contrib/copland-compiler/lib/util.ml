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

(** Declares a basic balanced tree map datastructure with string keys *)

open Core

(** Module defining how to treat strings as map keys *)
module StringKey : (Map.Key with type t = string) = struct
  type t = string
  let compare = String.compare
  let t_of_sexp = String.t_of_sexp
  let sexp_of_t = String.sexp_of_t
end

(** Module defining a map datastructure and its operations *)
module StringMap : (Map.S with type Key.t = string) = Map.Make(StringKey)
include StringMap

type arg_map = string list StringMap.t

(** Input a sequence of key value pairs to a StringMap *)
let make_arg_map (arg_map_list : (string * string list) list) : arg_map =
  List.fold_left ~init:StringMap.empty arg_map_list
    ~f:(fun map (arg_name, args) -> StringMap.add_exn map ~key:arg_name ~data:args)