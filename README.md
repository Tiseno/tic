# tic
Command line http client.

## Features
* Reading openapi files from predefined locations
* Profiles for different setups and environments
* Environments for different security settings and variables
* Persisting of entered parameters, request bodies, and tokens

## Install
```
make install
```
Will install tic into your cargo bin directory, usually `/home/username/.cargo/bin/`.

## Usage
To use tic, you need a configuration in your current directory or home folder named `.tic-config.json`.
`.tic-config.example.json` contains an example of what the file can contain.

#### apis
A list of services specified by a domain and the path to an openapi version 3 file in json format. All requests to the service will be made to the domain with current profile protocol prepended and tld appended.

#### profiles
Each containing a protocol, top level domain, reference to an environment name, and reference to a data_path name.

#### data_paths
Each containing a name, a path referring to a json file which will persist data entered such as parameters and request bodies.

#### environments
Each containing a name, a path referring to a json file which will persist any token entered, and a path to a public key for jwt validation.

