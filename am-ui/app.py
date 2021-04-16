# Copyright 2021 United States Government
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#

#
# app.py: Web application that serves the Attestation Manager UI.
# 


#!flask/bin/python
from flask import Flask, jsonify, request, render_template
import subprocess
import select


app = Flask(__name__, template_folder="am-ui-templates")


steps = []



@app.route("/clear", methods=['PUT'])
def clear():
    steps.clear()
    return jsonify({'steps' : steps})

@app.route("/onestep", methods=['GET'])
def my_func():
    return jsonify({'steps' : steps})

@app.route('/steps', methods=['GET'])
def get_steps():
    return render_template('maat-am-ui.html', steps=steps)

@app.route('/update/steps', methods=['POST', 'PUT', 'GET'])
def update_steps():
    steps.append((request.args.get("dir"), request.args.get("message")))
    return jsonify({'steps': steps})
    
if __name__ == '__main__':
    app.run(debug=True)

