Copyright
=========

Copyright 2023 United States Government

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. 


Simplified/Stream Graph (sgraph) Library
========================================

*This library is still under active development and all usage should be 
considered experimental*

The sgraph library is slated to be a replacement for the filesystem-based graph
library located at maat/lib/graph/. 

Instead of storing measurement graphs on the filesystem, this library will 
instead store graphs as structured data that can be passed between measurement
agents in a stream (e.g., via a pipe). Another goal of sgraph is to simplify the
usage of types within the graph; full adoption of sgraph with likely end in 
removal of all types in the source code (everything in maat/src/types/).