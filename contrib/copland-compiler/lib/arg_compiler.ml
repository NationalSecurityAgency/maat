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
open State
open Util
open Copland
open Ccode
open Apb
open Asp
open Primitives

type pid = expr

(** Produces code that initializes the mutex for managing access to critical
    sections of APB code *)
let init_mutex : (pfunc, unit, pfunc) State.t =
  let%bind mutex = get_mutex in
  let%bind _ = append_local ("sem_t *", mutex, None) in
  let%bind _ =
    append_statement
      (Assign
         ( Var mutex,
           CallExpr
             ( "sem_open",
               [
                 StringLit mutex;
                 EnumLit "O_CREAT | O_EXCL";
                 IntLit 420;
                 IntLit 1;
               ] ) ))
  in
  let%bind mutex_clean = fresh_ident "mutex_clean" in
  let%bind _ =
    prepend_cleanup mutex_clean
      (Ccode.Primitives.Seq
         ( Expr (CallExpr ("sem_unlink", [ StringLit mutex ])),
           Expr (CallExpr ("sem_close", [ Var mutex ])) ))
  in
  return ()

(** Produces code to grab the mutex for managing access to critical sections of
    APB code *)
let grab_mutex : (pfunc, unit, pfunc) State.t =
  let%bind mutex = get_mutex in
  let%bind _ = append_statement (Expr (CallExpr ("sem_wait", [ Var mutex ]))) in
  return ()

(** Produces code to release the mutex for managing access to critical sections
    of APB code *)
let release_mutex : (pfunc, unit, pfunc) State.t =
  let%bind mutex = get_mutex in
  let%bind _ = append_statement (Expr (CallExpr ("sem_post", [ Var mutex ]))) in
  return ()

(** Generates code to wait on a process id, causing the program to synchronously
    stop until the relavant process stops. *)
let wait_pid (p : pid) : (pfunc, unit, pfunc) State.t =
  let%bind _ = make_waitpid_pf p in
  return ()

(** Create measurement variable depending on asp target type *)
let create_meas_var (asp : asp_t) (arg : expr) (addr : ident) (pathvar : ident)
    =
  let%bind _ =
    append_comment
    @@ sprintf "creating measurement var for asp: %s with address_type: %s"
         asp.asp_name asp.address_type
  in
  match asp.address_type with
  | "pid_address_space" ->
      let%bind mvar_pid = fresh_ident "measurement_var_pid" in
      let%bind _ = append_local ("pid_t", mvar_pid, None) in
      let%bind _ =
        append_statement (Assign (Var mvar_pid, CallExpr ("atoi", [ arg ])))
      in
      let%bind _ =
        append_statement
          (Assign
             ( Var pathvar,
               CallExpr
                 ( "new_measurement_variable",
                   [ UnExpr (AddrOf, Var asp.target_type); Var addr ] ) ))
      in
      let pid_addr_lhs =
        BinExpr
          ( Deref,
            Cast ("pid_mem_range *", BinExpr (Deref, Var pathvar, Var "address")),
            Var "pid" )
      in
      let%bind _ = append_statement (Assign (pid_addr_lhs, Var mvar_pid)) in
      return ()
  | _ ->
      let%bind _ =
        append_statement
          (Assign
             ( Var pathvar,
               CallExpr
                 ( "new_measurement_variable",
                   [ UnExpr (AddrOf, Var asp.target_type); Var addr ] ) ))
      in
      let filepath_lhs =
        BinExpr
          ( Deref,
            Cast ("file_addr *", BinExpr (Deref, Var pathvar, Var "address")),
            Var "fullpath_file_name" )
      in
      let%bind _ =
        append_statement (Assign (filepath_lhs, CallExpr ("strdup", [ arg ])))
      in
      return ()

(** Generates code that produces an expression containing the node id of a file
    argument to an asp. If the file does not already have a corresponding node
    in the measurement with the corresponding target type, the code will
    initialize one. *)
let get_node_id_str (asp : asp_t) (arg : expr) : (pfunc, expr, pfunc) State.t =
  let%bind _ =
    append_comment @@ sprintf "getting node id of arg: %s" (c_of_expr arg)
  in
  let%bind pathvar = fresh_ident "pathvar" in
  let%bind _ = append_local ("measurement_variable *", pathvar, None) in
  let%bind addr = fresh_ident "addr" in
  let%bind _ = append_local ("address *", addr, None) in
  let%bind _ = grab_mutex in
  let%bind _ =
    append_statement
      (Assign
         ( Var addr,
           CallExpr ("alloc_address", [ UnExpr (AddrOf, Var asp.address_type) ])
         ))
  in
  let%bind _ = create_meas_var asp arg addr pathvar in
  let%bind node_id = fresh_ident "node_id" in
  let%bind nid_str = fresh_ident "node_id_str" in
  let%bind _ = append_local ("node_id_t", node_id, None) in
  let%bind _ = append_local ("node_id_str", nid_str, None) in
  let%bind gvar = get_graphvar in
  let%bind nodeset = get_node_hashset in
  let%bind _ =
    append_statement
      (Assign
         ( Var node_id,
           CallExpr ("measurement_graph_get_node", [ Var gvar; Var pathvar ]) ))
  in
  let%bind _, stmt =
    stmt_of_comp_scope
    @@
    let%bind _ =
      append_statement
        (Expr
           (CallExpr
              ( "measurement_graph_add_node",
                [
                  Var gvar;
                  Var pathvar;
                  EnumLit "NULL";
                  UnExpr (AddrOf, Var node_id);
                ] )))
    in
    let%bind node_id_ptr = fresh_ident "node_id_ptr" in
    let%bind _ = append_local ("node_id_t *", node_id_ptr, None) in
    let%bind _ =
      append_statement
        (Assign
           ( Var node_id_ptr,
             CallExpr
               ("malloc", [ CallExpr ("sizeof", [ EnumLit "node_id_t" ]) ]) ))
    in
    let%bind _ =
      append_statement
        (Assign (UnExpr (PointsTo, Var node_id_ptr), Var node_id))
    in
    let%bind _ =
      append_statement
        (Expr (CallExpr ("g_hash_table_add", [ Var nodeset; Var node_id_ptr ])))
    in
    return ()
  in
  let%bind _ =
    append_if
      (BinExpr (Eq, Var node_id, EnumLit "INVALID_NODE_ID"))
      [ stmt ] None
  in
  let%bind _ =
    append_statement
      (Expr (CallExpr ("str_of_node_id", [ Var node_id; Var nid_str ])))
  in
  let%bind _ = release_mutex in
  return @@ Var nid_str

(** Generates code that takes a list of file names, finds corresponding
    measurement graph nodes, populates an array with them, and returns the array
    along with its length *)
let get_nodes_arg_list (asp : asp_t) (args : string list) :
    (pfunc, expr * expr, pfunc) State.t =
  let%bind node_arr_id = fresh_ident "node_arr" in
  let%bind node_arr_len = fresh_ident "node_arr_len" in
  let%bind _ = append_local ("char *", node_arr_id, Some (List.length args)) in
  let%bind _ = append_local ("int", node_arr_len, None) in
  let%bind _ =
    append_statement (Assign (Var node_arr_len, IntLit (List.length args)))
  in
  let%bind _ =
    State.iteri args ~f:(fun i arg ->
        let%bind node_id_str = get_node_id_str asp (StringLit arg) in
        let%bind _ =
          append_statement
            (Assign (Subscript (Var node_arr_id, IntLit i), node_id_str))
        in
        return ())
  in
  return @@ (Var node_arr_id, Var node_arr_len)

(** Generates code that returns a queue populated with all nodes added to the
    graph since the previous time the get_new_variables function was called *)
let update_node_set : (pfunc, expr, pfunc) State.t =
  let%bind node_hashset = get_node_hashset in
  let%bind graph = get_graphvar in
  let%bind node_queue = fresh_ident "node_queue" in
  let%bind _ = append_local ("GQueue *", node_queue, None) in
  let%bind _ = grab_mutex in
  let%bind _ =
    append_statement
      (Assign
         ( Var node_queue,
           CallExpr ("get_new_variables", [ Var graph; Var node_hashset ]) ))
  in
  let%bind _ = release_mutex in
  return @@ Var node_queue

(** Generates code that checks the reutrn value of an asp for an error, logging
    the error if it occurs *)
let log_error (ret_val : expr) (node_id_str : expr) (asp_name : string) :
    (pfunc, unit, pfunc) State.t =
  append_if
    (BinExpr (Lt, ret_val, IntLit 0))
    [
      Expr
        (CallExpr
           ( "dlog",
             [
               IntLit 6;
               StringLit
                 (Printf.sprintf
                    "ASP: %s returned value %s when called on node %s" asp_name
                    "%d" "%s");
               ret_val;
               node_id_str;
             ] ));
    ]
    None

(** Generates code that runs an asp on each element of a node array *)
let run_asp_on_nodes (asp : asp_t) (asp_var : expr) (node_arr : expr)
    (node_arr_len : expr) (target : expr) : (pfunc, unit, pfunc) State.t =
  (* is there some risk that I am piping states incorrectly *)
  let%bind rcvar = get_rcvar in
  let%bind index = fresh_ident "i" in
  let%bind _ = append_local ("int", index, None) in
  let%bind _ =
    append_comment
    @@ Printf.sprintf "running asp %s on all arguments" asp.asp_name
  in
  let%bind _ = append_statement (Assign (Var index, IntLit 0)) in
  let%bind _, body =
    stmt_of_comp_scope
    @@
    let%bind asp_argv = fresh_ident @@ Printf.sprintf "%s_argv" asp.asp_name in
    let%bind _ = append_local ("char *", asp_argv, Some 2) in
    let%bind _ =
      append_statement (Assign (Subscript (Var asp_argv, IntLit 0), target))
    in
    let%bind _ =
      append_statement
        (Assign
           (Subscript (Var asp_argv, IntLit 1), Subscript (node_arr, Var index)))
    in
    let%bind _ = grab_mutex in
    let%bind _ =
      append_statement
        (Assign
           ( Var rcvar,
             CallExpr
               ( "run_asp",
                 [
                   asp_var;
                   IntLit (-1);
                   IntLit (-1);
                   EnumLit "false";
                   IntLit 2;
                   Var asp_argv;
                 ] ) ))
    in
    let%bind _ = release_mutex in
    let%bind _ =
      log_error (Var rcvar) (Subscript (node_arr, Var index)) asp.asp_name
    in
    (* add back in error messages*)
    let%bind _ =
      append_statement (Assign (Var index, BinExpr (Add, Var index, IntLit 1)))
    in
    return ()
  in
  append_while (BinExpr (Lt, Var index, node_arr_len)) body

(** Generates code to free all the memory allocated to an input_queue if it is
    not None *)
let discard_queue (input_queue : expr option option) :
    (pfunc, unit, pfunc) State.t =
  match input_queue with
  | None | Some None -> return ()
  | Some (Some q) ->
      (* g_queue_clear_full calls free on all elements of the queue*)
      let%bind _ =
        append_statement
          (Expr
             (CallExpr
                ( "g_queue_free_full",
                  [ q; Cast ("GDestroyNotify", EnumLit "free") ] )))
      in
      return ()

(** Generates code to merge two possibly present input queues. An input of None
    represents no input. An input of Some None represents the case where the
    previous phrase produced new nodes but the queue has not yet been computed.
    In this case, the code creates the queue. *)
let rec merge_queues (queue1 : expr option option) (queue2 : expr option option)
    : (pfunc, expr option option, pfunc) State.t =
  match (queue1, queue2) with
  | None, _ -> return queue2
  | _, None -> return queue1
  | Some None, _ ->
      let%bind q = update_node_set in
      merge_queues (Some (Some q)) queue2
  | _, Some None ->
      let%bind q = update_node_set in
      merge_queues queue1 (Some (Some q))
  | Some (Some q1), Some (Some q2) ->
      let%bind _ =
        append_statement (Expr (CallExpr ("g_queue_compose", [ q1; q2 ])))
      in
      return (Some (Some q1))

(** Generates code to copy a possibly present input queue. An input of None
    represents no input. An input of Some None represents the case where the
    previous phrase produced new nodes but the queue has not yet been computed.
    In this case, the code creates the queue. *)
let copy_queue (input_queue : expr option option) :
    (pfunc, expr option option * expr option option, pfunc) State.t =
  match input_queue with
  | None -> return (None, None)
  | Some None ->
      let%bind q = update_node_set in
      let%bind copy = fresh_ident "node_queue_copy" in
      let%bind _ = append_local ("g_queue *", copy, None) in
      let%bind _ =
        append_statement
          (Assign (Var copy, CallExpr ("g_queue_deep_copy", [ q ])))
      in
      return (Some (Some q), Some (Some (Var copy)))
  | Some (Some q) ->
      let%bind copy = fresh_ident "node_queue_copy" in
      let%bind _ = append_local ("g_queue *", copy, None) in
      let%bind _ =
        append_statement
          (Assign (Var copy, CallExpr ("g_queue_deep_copy", [ q ])))
      in
      return (Some (Some q), Some (Some (Var copy)))

(** Generates code to to migrate the nodes in a queue to an array with a
    precomputed length that has been populated with pointers to allocated blocks
    of memory large enough to hold the node id strings *)
let transfer_queue_to_arr (queue : expr) (arr : expr) (len : expr) :
    (pfunc, unit, pfunc) State.t =
  let%bind _ = append_comment "transferring values in queue to array" in
  let%bind index = fresh_ident "i" in
  let%bind _ = append_local ("int", index, None) in
  let%bind node_id = fresh_ident "node_id_ptr" in
  let%bind _ = append_local ("node_id_t *", node_id, None) in
  let%bind node_id_str = fresh_ident "node_str" in
  let%bind _ = append_local ("node_id_str", node_id_str, None) in
  let%bind _, body =
    stmt_of_comp_scope
    @@
    let%bind _ =
      append_statement
        (Assign (Var node_id, CallExpr ("g_queue_pop_head", [ queue ])))
    in
    let%bind _ =
      append_statement
        (Expr
           (CallExpr
              ( "str_of_node_id",
                [ UnExpr (PointsTo, Var node_id); Var node_id_str ] )))
    in
    let%bind _ =
      append_statement
        (Expr
           (CallExpr ("strcpy", [ Subscript (arr, Var index); Var node_id_str ])))
    in
    let%bind _ =
      append_statement (Assign (Var index, BinExpr (Add, Var index, IntLit 1)))
    in
    let%bind _ =
      append_statement
        (Expr (CallExpr ("memset", [ Var node_id_str; IntLit 0; IntLit 17 ])))
    in
    return ()
  in
  let%bind _ = append_while (BinExpr (Lt, Var index, len)) body in
  let%bind _ =
    append_statement
      (Expr
         (CallExpr
            ( "g_queue_free_full",
              [ queue; Cast ("GDestroyNotify", EnumLit "free") ] )))
  in
  return ()

(** Generates code to migrate the node id strings from an input queue to an
    ouptut array along with its length *)
let get_nodes_queue (input_queue : expr) : (pfunc, expr * expr, pfunc) State.t =
  let%bind _ =
    append_comment @@ Printf.sprintf "transfering nodes from queue to array"
  in
  let%bind queue_len = fresh_ident "qlenth" in
  let%bind _ = append_local ("int", queue_len, None) in
  let%bind _ =
    append_statement
      (Assign (Var queue_len, CallExpr ("g_queue_get_length", [ input_queue ])))
  in
  let%bind new_node_arr = fresh_ident "new_node_arr" in
  let%bind _ = append_local ("char **", new_node_arr, None) in
  let%bind _ =
    append_comment
    @@ Printf.sprintf "allocating memory for node array: %s" new_node_arr
  in
  let%bind _ =
    append_statement
      (Assign
         ( Var new_node_arr,
           CallExpr
             ( "malloc",
               [
                 BinExpr
                   ( Mul,
                     Var queue_len,
                     CallExpr ("sizeof", [ EnumLit "char *" ]) );
               ] ) ))
  in
  let%bind index = fresh_ident "i" in
  let%bind _ = append_local ("int", index, None) in
  let%bind _ = append_statement (Assign (Var index, IntLit 0)) in
  let%bind _, stmt =
    stmt_of_comp_scope
    @@
    let%bind _ =
      append_statement
        (Assign
           ( Subscript (Var new_node_arr, Var index),
             CallExpr
               ( "malloc",
                 [
                   BinExpr
                     (Mul, IntLit 17, CallExpr ("sizeof", [ EnumLit "char" ]));
                 ] ) ))
    in
    let%bind _ =
      append_statement (Assign (Var index, BinExpr (Add, Var index, IntLit 1)))
    in
    return ()
  in
  let%bind _ = append_while (BinExpr (Lt, Var index, Var queue_len)) stmt in
  let%bind _ =
    transfer_queue_to_arr input_queue (Var new_node_arr) (Var queue_len)
  in
  return (Var new_node_arr, Var queue_len)

(* Generate code to compute an array containing all of the node id strings to run an asp on along with its length *)
let get_nodes (asp : asp_t) (args_map : arg_map) (arg_label : string)
    (input_queue : expr option option) : (pfunc, expr * expr, pfunc) State.t =
  match arg_label with
  | "children" -> (
      match input_queue with
      | None -> failwith "invalid copland phrase"
      | Some None ->
          let%bind q = update_node_set in
          get_nodes_queue q
      | Some (Some q) -> get_nodes_queue q)
  | _ ->
      let%bind _ = discard_queue input_queue in
      let args_opt = StringMap.find args_map arg_label in
      get_nodes_arg_list asp (Option.value args_opt ~default:[ arg_label ])

let process_target (target : string) : (pfunc, expr, pfunc) State.t =
  let%bind target_opt = handle_special_arg (StringLit target) in
  match target_opt with
  | Some target' -> return target'
  | None -> return (StringLit target)

(** Free the memory allocated at the top level to an array if it was not stack
    allocated. Such an array will be heap allocated if and only if the
    input_queue is not None*)
let cleanup_node_arr (args : string list) (node_arr : expr) :
    (pfunc, unit, pfunc) State.t =
  if List.exists ~f:(fun arg -> String.equal arg "children") args then
    append_statement (Expr (CallExpr ("free", [ node_arr ])))
  else return ()

(** Generates code to execute an asp on the proper list of arguments *)
let compile_asp (args_map : arg_map) (cmd : string) (target : string)
    (args : string list) (input_queue : expr option option) :
    (pfunc, expr, pfunc) State.t =
  let%bind asp_var = find_asp cmd in
  let%bind _ = append_comment @@ sprintf "running asp %s" cmd in
  let asp_rec = Asp.get_asp cmd in
  let%bind _ =
    append_comment @@ Printf.sprintf "setting up arguments for asp %s" cmd
  in
  let%bind node_arr, len =
    get_nodes asp_rec args_map (List.hd_exn args) input_queue
  in
  let%bind target_expr = process_target target in
  let%bind _ = run_asp_on_nodes asp_rec asp_var node_arr len target_expr in
  let%bind _ = cleanup_node_arr args node_arr in
  let%bind output_queue = update_node_set in
  return output_queue

(** Generates code to initialize a glib hashset *)
let init_hashset : (pfunc, unit, pfunc) State.t =
  let%bind node_hashset = get_node_hashset in
  let%bind _ = append_local ("GHashTable *", node_hashset, None) in
  let%bind _ = append_comment "initializing node hash table" in
  let%bind _ =
    append_statement
      (Assign
         ( Var node_hashset,
           CallExpr
             ( "g_hash_table_new",
               [ EnumLit "g_int64_hash"; EnumLit "g_int64_equal" ] ) ))
  in
  return ()

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
let rec compile_wf (args_map : arg_map) (w : workflow)
    (input_queue : expr option option) :
    (pfunc, pid list * expr option option, pfunc) State.t =
  match w with
  | SIG ->
      let%bind _ = sign_meas in
      return ([], None)
  | PRIM { cmd; target; args } ->
      let%bind queue = compile_asp args_map cmd target args input_queue in
      return ([], Some (Some queue))
  | BRNCH (SEQ, flow) ->
      let left = flow.left in
      let right = flow.right in
      let%bind input1, input2 = copy_queue input_queue in
      let%bind pids1, output_queue1 = compile_wf args_map left input1 in
      let%bind _ = State.iter ~f:wait_pid pids1 in
      let%bind pids2, output_queue2 = compile_wf args_map right input2 in
      let%bind output_queue3 = merge_queues output_queue1 output_queue2 in
      return (pids2, output_queue3)
  | BRNCH (CONC, flow) ->
      let left = flow.left in
      let right = flow.right in
      let%bind input1, input2 = copy_queue input_queue in
      let%bind pid1 =
        async_run
        @@
        let%bind pids, output_queue = compile_wf args_map left input1 in
        let%bind _ = State.iter ~f:wait_pid pids in
        let%bind _ = discard_queue output_queue in
        return ()
      in
      let%bind pid2 =
        async_run
        @@
        let%bind pids, output_queue = compile_wf args_map right input2 in
        let%bind _ = State.iter ~f:wait_pid pids in
        let%bind _ = discard_queue output_queue in
        return ()
      in
      return ([ pid1; pid2 ], Some None)
  | LIN (SEQ, { first; second }) ->
      let%bind pids1, output_queue = compile_wf args_map first input_queue in
      let%bind _ = State.iter ~f:wait_pid pids1 in
      compile_wf args_map second output_queue
  | LIN (CONC, _) ->
      failwith "unimplemented: this is not actually a legal copland phrase"
  | AT _ -> failwith "unimplemented"

(** Produces a string containing the body of a C file implementing a Copland
    workflow with specified arguements Relies on the compile_wf function and
    provides a context for the code produced by compile_wf to run. *)
let compile (args_map : arg_map) (w : workflow) =
  let pf =
    eval
      (let%bind _ = init_meas_graph in
       let%bind _ = init_mutex in
       let%bind _ = init_hashset in
       let%bind pids, q = compile_wf args_map w None in
       let%bind _ = State.iter ~f:wait_pid pids in
       let%bind _ = discard_queue q in
       let%bind pf = get in
       return pf)
      (Ccode.mkpfunc ~name:"apb_execute"
         ~args:
           [
             ("struct apb", "*apb");
             ("struct scenario", "*scen UNUSED");
             ("uuid_t", "meas_spec UNUSED");
             ("int", "peerchan");
             ("int", "resultchan");
             ("char", "*target UNUSED");
             ("char", "*target_type UNUSED");
             ("struct key_value", "**arg_list UNUSED");
             ("int", "argc UNUSED");
           ]
         ~rc:"rc" ~graphvar:"graphvar" ~graphpathvar:"graphpathvar"
         ~node_hashset:"node_hashset" ())
  in
  c_of_pfunc pf
