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

(** A stateful computation is a function from initial state (of type {i 'a}) to
    a return value (of type {i 'b}) and a final state (of type {i 'c}). *)
type ('a, 'b, 'c) t = 'a -> 'b * 'c

(** Return a value, threading the current state through unchanged. *)
val return : 'b -> ('a, 'b, 'a) t

(** Return the current state and thread it through unchanged. *)
val get : ('a, 'a, 'a) t

(** Replace the current state with a new value and return unit. *)
val put : 'b -> ('a, unit, 'b) t

(** Given an initial state, run the state function and return the pair of
    {i (return val, final state)} *)
val run : ('a, 'b, 'c) t -> 'a -> 'b * 'c

(** Like {!val:run} but discard the final state and return only the value part *)
val eval : ('a, 'b, 'c) t -> 'a -> 'b

(** Create a new stateful computation by composing the computation {!val:x} with
    the function {!val:f}. *)
val bind : ('a, 'b, 'c) t -> ('b -> ('c, 'd, 'e) t) -> ('a, 'd, 'e) t

(** Infix form of {!val:bind} *)
val ( >>= ) : ('a, 'b, 'c) t -> ('b -> ('c, 'd, 'e) t) -> ('a, 'd, 'e) t

(** Create a new stateful computation by passing the return value of {!val:x} to
    {!val:f} and threading the state through unchanged. *)
val map : ('a, 'b, 'c) t -> ('b -> 'd) -> ('a, 'd, 'c) t

(** Infix form of {!val:map} *)
val ( >|= ) : ('a, 'b, 'c) t -> ('b -> 'd) -> ('a, 'd, 'c) t

(** {!val:List.fold_left} for stateful computations. Threads state through
    application of {!val:f} to an accumulator (starting with {!val:init}) and
    each element of the list {!val:l} *)
val fold :
  f:('x -> 'y -> ('a, 'x, 'a) t) -> init:'x -> 'y list -> ('a, 'x, 'a) t



(** {!val:List.iter} for stateful computations. Threads state through the
    application of {!val:f} to each element of the list {!val:l} *)  
val iter : f:('x -> ('a, unit, 'a) t) -> 'x list -> ('a, unit, 'a) t

(** {!val:List.iter} for stateful computations. Threads state through the
    application of {!val:f} to each element, along with its index, of the list
    {!val:l} *)
val iteri : f:(int -> 'x -> ('a, unit, 'a) t) -> 'x list -> ('a, unit, 'a) t

(** Module defining {!val:map} and {!val:bind} with labeled {!val:~f} argument
    for use with {b ppx_let} syntax extension. *)
module Let_syntax : sig
  val map : ('a, 'b, 'c) t -> f:('b -> 'd) -> ('a, 'd, 'c) t
  val bind : ('a, 'b, 'c) t -> f:('b -> ('c, 'd, 'e) t) -> ('a, 'd, 'e) t
end
