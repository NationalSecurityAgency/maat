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

open Core

(** A stateful computation is a function from initial state (of type {i 'a}) to
    a return value (of type {i 'b}) and a final state (of type {i 'c}). *)
type ('a, 'b, 'c) t = 'a -> 'b * 'c

(** Return a value, threading the current state through unchanged. *)
let return : 'b -> ('a, 'b, 'a) t = fun v state -> (v, state)

(** Return the current state and thread it through unchanged. *)
let get : ('a, 'a, 'a) t = fun state -> (state, state)

(** Replace the current state with a new value and return unit. *)
let put : 'b -> ('a, unit, 'b) t = fun x _ -> ((), x)

(** Given an initial state, run the state function and return the pair of
    {i (return val, final state)} *)
let run : ('a, 'b, 'c) t -> 'a -> 'b * 'c = fun f state -> f state

(** Like {!val:run} but discard the final state and return only the value part *)
let eval : ('a, 'b, 'c) t -> 'a -> 'b = fun f s -> run f s |> fst

(** Create a new stateful computation by composing the computation {!val:x} with
    the function {!val:f}. *)
let bind : ('a, 'b, 'c) t -> ('b -> ('c, 'd, 'e) t) -> ('a, 'd, 'e) t =
 fun x f state ->
  let i, state = run x state in
  run (f i) state

(** Infix form of {!val:bind} *)
let ( >>= ) x f = bind x f

(** Create a new stateful computation by passing the return value of {!val:x} to
    {!val:f} and threading the state through unchanged. *)
let map : ('a, 'b, 'c) t -> ('b -> 'd) -> ('a, 'd, 'c) t =
 fun x f state ->
  let i, state = run x state in
  run (return (f i)) state

(** Infix form of {!val:map} *)
let ( >|= ) x f = map x f

(** {!val:List.fold_left} for stateful computations. Threads state through
    application of {!val:f} to an accumulator (starting with {!val:init}) and
    each element of the list {!val:l} *)
let fold ~(f : 'x -> 'y -> ('a, 'x, 'a) t) ~(init : 'x) (l : 'y list) :
    ('a, 'x, 'a) t =
 fun state -> List.fold_left ~f:(fun (a, c) b -> f a b c) ~init:(init, state) l

(** {!val:List.iter} for stateful computations. Threads state through the
    application of {!val:f} to each element of the list {!val:l} *)
let iter ~(f : 'x -> ('a, unit, 'a) t) (l : 'x list) : ('a, unit, 'a) t =
 fun state -> List.fold_left ~f:(fun ((), c) a -> f a c) ~init:((), state) l

(** {!val:List.iter} for stateful computations. Threads state through the
    application of {!val:f} to each element, along with its index, of the list
    {!val:l} *)
let iteri ~(f : int -> 'x -> ('a, unit, 'a) t) (l : 'x list) : ('a, unit, 'a) t
    =
  iter ~f:(fun (i, x) -> f i x) (List.mapi ~f:(fun i x -> (i, x)) l)

(** Module defining {!val:map} and {!val:bind} with labeled {!val:~f} argument
    for use with {b ppx_let} syntax extension. *)
module Let_syntax = struct
  let map a ~f = map a f
  let bind a ~f = bind a f
end
