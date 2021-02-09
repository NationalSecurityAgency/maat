(**
 * Copyright 2020 United States Government
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

open Core;;
let cmd =
    let open Command.Let_syntax in
    let open Command.Param in
    Command.basic
        ~summary:"Concatenate input from left and right file descriptors given on command line"
        (let%map sep = flag "--separator" (optional_with_default "\n" string)                           
                           ~doc:"Output the given separator string between the left and right inputs."
         and pfx     = flag "--prefix" (optional_with_default "\n" string)
                           ~doc:"Output the given prefix string before the left input."
         and sfx     = flag "--suffix" (optional_with_default "\n" string)
                           ~doc:"Output the given suffix string after the right input."
         and l = anon ("leftfd" %: int)
         and r = anon ("rightfd" %: int) in
         (fun () ->
              let lchan = Unix.in_channel_of_descr (Unix.File_descr.of_int l) in
              let rchan = Unix.in_channel_of_descr (Unix.File_descr.of_int r) in
              Out_channel.output_string Out_channel.stdout pfx;
              In_channel.input_all lchan |> Out_channel.output_string Out_channel.stdout;
              Out_channel.output_string Out_channel.stdout sep ;
              In_channel.input_all rchan |> Out_channel.output_string Out_channel.stdout;
              Out_channel.output_string Out_channel.stdout sfx))
                                  
let _ = Command.run ~version:"1.0" ~build_info:"RWO" cmd
