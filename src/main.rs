use inquire::{validator::Validation, Editor, InquireError, Select, Text};
use jsonwebtoken::DecodingKey;
use openapiv3::{OpenAPI, Operation};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs};

#[derive(Serialize, Deserialize, Debug)]
struct Jwt {
    pub exp: u64,
}

fn json_formatter(s: String) -> Result<String, serde_json::Error> {
    let json_value: serde_json::Value = serde_json::from_str(&s)?;

    serde_json::to_string_pretty(&json_value)
}

fn read_openapi_from_path_with_removed_security_schemes(path: &str) -> OpenAPI {
    let openapi_string = fs::read_to_string(path)
        .unwrap_or_else(|_| panic!("Could not read '{}' openapi file", path));

    let mut val: serde_json::Value = serde_json::from_str(&openapi_string)
        .unwrap_or_else(|_| panic!("Could not deserialize '{}' openapi", path));

    val.get_mut("components")
        .unwrap_or_else(|| {
            panic!(
                "Could not get mutable ref to field \"components\" in '{}' openapi",
                path
            )
        })
        .as_object_mut()
        .unwrap_or_else(|| {
            panic!(
                "Could not have ref as object to \"components\" in '{}' openapi",
                path
            )
        })
        .remove("securitySchemes");

    let api: OpenAPI = serde_json::from_str(&val.to_string())
        .unwrap_or_else(|_| panic!("Could not deserialize '{}' openapi to OpenAPI", path));

    api
}

#[derive(Deserialize, Debug)]
struct TicEnvironment {
    name: String,
    public_pem_path: String,
}

#[derive(Deserialize, Debug)]
struct TicProfile {
    name: String,
    protocol: String,
    tld: String,
    env: String,
    #[allow(dead_code)]
    data: String,
}

#[derive(Deserialize, Debug)]
struct TicApiPath {
    path: String,
    domain: String,
}

#[derive(Deserialize, Debug)]
struct TicConfig {
    environments: Vec<TicEnvironment>,
    profiles: Vec<TicProfile>,
    apis: Vec<TicApiPath>,
}

struct ApiDefinition {
    domain: String,
    open_api: OpenAPI,
}

#[derive(Debug)]
struct TicOperation {
    name: String,
    path: String,
    method: Method,
    #[allow(dead_code)]
    operation: Operation,
}

impl TicOperation {
    fn maybe_from(path: &str, op: &Option<Operation>, method: Method) -> Option<Self> {
        op.as_ref().map(|op| TicOperation {
            name: format!("{} {}", method, path.to_owned()),
            path: path.to_owned(),
            method,
            operation: op.to_owned(),
        })
    }
}

fn main() {
    let config_string = fs::read_to_string(".tic-config.json").unwrap_or_else(|_| {
        fs::read_to_string("~/.tic-config.json").expect("Could not read configuration file")
    });

    let config: TicConfig =
        serde_json::from_str(&config_string).expect("Could not parse configuration file");

    let apis: Vec<ApiDefinition> = config
        .apis
        .iter()
        .map(|TicApiPath { path, domain }| ApiDefinition {
            domain: domain.to_owned(),
            open_api: read_openapi_from_path_with_removed_security_schemes(path),
        })
        .collect();

    let mut env_data = std::collections::HashMap::<String, String>::new();

    select_profile_loop(config, apis, &mut env_data);
}

fn select_profile_loop(
    config: TicConfig,
    apis: Vec<ApiDefinition>,
    env_data: &mut HashMap<String, String>,
) {
    loop {
        let selected_profile_index = match Select::new(
            "profile",
            config
                .profiles
                .iter()
                .map(|profile| profile.name.to_owned())
                .collect(),
        )
        .with_vim_mode(true)
        .raw_prompt()
        .map(|op| op.index)
        {
            Ok(i) => i,
            Err(InquireError::OperationCanceled) => break,
            Err(InquireError::OperationInterrupted) => std::process::exit(0),
            _ => todo!(),
        };

        let selected_profile = &config.profiles[selected_profile_index];

        match config
            .environments
            .iter()
            .find(|a| a.name.eq(&selected_profile.env))
        {
            Some(environment) => {
                let pem_string = match fs::read_to_string(&environment.public_pem_path) {
                    Ok(ok) => ok,
                    Err(err) => {
                        println!("Error reading pem file {}", err);
                        break;
                    }
                };

                let decoding_key =
                    &jsonwebtoken::DecodingKey::from_rsa_pem(pem_string.as_bytes()).unwrap();

                select_api_loop(selected_profile, decoding_key, &apis, env_data);
            }
            None => {
                println!(
                "Could not find environment with name '{}' in configuration specified by profile '{}'.",
                selected_profile.env, selected_profile.name,
            );
            }
        }
    }
}

fn select_api_loop(
    selected_profile: &TicProfile,
    decoding_key: &DecodingKey,
    apis: &[ApiDefinition],
    env_data: &mut HashMap<String, String>,
) {
    // TODO load/save persisted
    // env/data into the ctx
    // from defined environment
    // by the profile
    let mut data = std::collections::HashMap::<String, String>::new();
    loop {
        let selected_api_index = match Select::new(
            "api",
            apis.iter()
                .map(
                    |ApiDefinition {
                         domain: _,
                         open_api,
                     }| {
                        format!(
                            "{} {}",
                            open_api.info.title.clone(),
                            open_api.info.version.clone()
                        )
                    },
                )
                .collect(),
        )
        .with_vim_mode(true)
        .raw_prompt()
        .map(|op| op.index)
        {
            Ok(i) => i,
            Err(InquireError::OperationCanceled) => break,
            Err(InquireError::OperationInterrupted) => std::process::exit(0),
            _ => todo!(),
        };

        let selected_api = &apis[selected_api_index];

        // TODO do this for all apis at the beginning instead
        let operations: Vec<TicOperation> = selected_api
            .open_api
            .paths
            .iter()
            .filter_map(|(path, path_item_ref)| {
                path_item_ref.as_item().map(|path_item| (path, path_item))
            })
            .flat_map(|(path, path_item)| {
                vec![
                    TicOperation::maybe_from(path, &path_item.get, Method::GET),
                    TicOperation::maybe_from(path, &path_item.put, Method::PUT),
                    TicOperation::maybe_from(path, &path_item.post, Method::POST),
                    TicOperation::maybe_from(path, &path_item.patch, Method::PATCH),
                    TicOperation::maybe_from(path, &path_item.delete, Method::DELETE),
                ]
            })
            .flatten()
            .collect();

        select_operation_loop(
            &mut data,
            operations,
            selected_api,
            decoding_key,
            selected_profile,
            env_data,
        );
    }
}

fn select_operation_loop(
    data: &mut HashMap<String, String>,
    operations: Vec<TicOperation>,
    selected_api: &ApiDefinition,
    decoding_key: &DecodingKey,
    selected_profile: &TicProfile,
    env_data: &mut HashMap<String, String>,
) {
    loop {
        let selected_operation_index = match Select::new(
            "request",
            operations
                .iter()
                .map(
                    |TicOperation {
                         name,
                         path: _,
                         method: _,
                         operation: _,
                     }| name,
                )
                .collect(),
        )
        .with_vim_mode(true)
        .raw_prompt()
        .map(|op| op.index)
        {
            Ok(i) => i,
            Err(InquireError::OperationCanceled) => {
                break;
            }
            Err(InquireError::OperationInterrupted) => std::process::exit(0),
            _ => todo!(),
        };

        let selected_operation = &operations[selected_operation_index];

        request_loop(
            data,
            selected_api,
            decoding_key,
            selected_profile,
            selected_operation,
            env_data,
        );
    }
}

fn build_request_path(
    selected_profile: &TicProfile,
    selected_api: &ApiDefinition,
    selected_operation: &TicOperation,
    data: &mut HashMap<String, String>,
) -> String {
    let mut full_path_with_parameters = format!(
        "{}://{}{}{}",
        selected_profile.protocol,
        selected_api.domain,
        selected_profile.tld,
        selected_operation.path
    );

    selected_operation
        .operation
        .parameters
        .iter()
        .filter_map(|parameter| parameter.as_item())
        // TODO support optional parameters
        .filter(|parameter| parameter_is_required(parameter))
        .for_each(|parameter| {
            match parameter {
                openapiv3::Parameter::Path {
                    parameter_data,
                    style: _,
                } => {
                    full_path_with_parameters = full_path_with_parameters.replace(
                        &format!("{{{}}}", &parameter_name(parameter)),
                        data.get(&parameter_data.name).unwrap_or(&String::new()),
                    );
                }
                openapiv3::Parameter::Query {
                    parameter_data: _,
                    allow_reserved: _,
                    style: _,
                    allow_empty_value: _,
                } => {
                    todo!()
                }
                _ => todo!(),
            };
        });

    full_path_with_parameters
}

fn parameter_name(parameter: &openapiv3::Parameter) -> String {
    match parameter {
        openapiv3::Parameter::Path {
            parameter_data,
            style: _,
        } => parameter_data.name.to_owned(),
        openapiv3::Parameter::Query {
            parameter_data,
            allow_reserved: _,
            style: _,
            allow_empty_value: _,
        } => parameter_data.name.to_owned(),
        _ => todo!(),
    }
}

fn parameter_is_required(parameter: &openapiv3::Parameter) -> bool {
    match parameter {
        openapiv3::Parameter::Path {
            parameter_data,
            style: _,
        } => parameter_data.required,
        openapiv3::Parameter::Query {
            parameter_data,
            allow_reserved: _,
            style: _,
            allow_empty_value: _,
        } => parameter_data.required,
        _ => todo!(),
    }
}

fn format_parameter_name(parameter: &openapiv3::Parameter) -> String {
    match parameter {
        openapiv3::Parameter::Path {
            parameter_data,
            style: _,
        } => format!(
            "{{{}}}{}",
            parameter_data.name.to_owned(),
            if parameter_data.required.to_owned() {
                ""
            } else {
                " (optional)"
            }
        ),
        openapiv3::Parameter::Query {
            parameter_data,
            allow_reserved: _,
            style: _,
            allow_empty_value: _,
        } => format!(
            "?{}{}",
            parameter_data.name.to_owned(),
            if parameter_data.required.to_owned() {
                ""
            } else {
                " (optional)"
            }
        ),
        _ => todo!(),
    }
}

fn request_loop(
    data: &mut HashMap<String, String>,
    selected_api: &ApiDefinition,
    decoding_key: &DecodingKey,
    selected_profile: &TicProfile,
    selected_operation: &TicOperation,
    env_data: &mut HashMap<String, String>,
) {
    loop {
        let full_path = format!(
            "{}://{}{}{}",
            selected_profile.protocol,
            selected_api.domain,
            selected_profile.tld,
            selected_operation.path
        );

        println!("{} {}", selected_operation.method, full_path);

        let _r: Vec<String> = selected_operation
            .operation
            .parameters
            .iter()
            .filter_map(|parameter| parameter.as_item())
            // TODO support optional parameters
            .filter(|parameter| parameter_is_required(parameter))
            .map(|parameter| {
                let param_name = &parameter.parameter_data_ref().name.to_owned();
                match Text::new(&format_parameter_name(parameter)) // TODO search for options/data/ids
                                                                   // in the environment and use fuzzy
                                                                   // search and autocomplete
                    .with_initial_value(data.get(&param_name.to_owned()).unwrap_or(&"".to_owned()))
                    .prompt()
                {
                    Ok(ok) => {
                        if !ok.is_empty() {
                            data.insert(param_name.to_owned(), ok.to_owned());
                        }
                        ok
                    }
                    Err(InquireError::OperationCanceled) => "".to_owned(), // TODO make this break
                                                                           // the map and loop
                    Err(InquireError::OperationInterrupted) => std::process::exit(0),
                    _ => todo!(),
                }
            })
            .collect();

        // TODO set query parameters

        // TODO show full request with parameters and show confirm for send/edit

        if let Some(token) = env_data.get(&selected_profile.env) {
            match jsonwebtoken::decode::<Jwt>(
                token,
                decoding_key,
                &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256),
            ) {
                Ok(_) => (),
                Err(error) => {
                    println!(
                        "Removed invalid token for env '{}': {}",
                        &selected_profile.env, error
                    );
                    env_data.remove(&selected_profile.env);
                }
            }
        }

        if env_data.get(&selected_profile.env).is_none() {
            let decoding_key = decoding_key.clone();
            let validator = move |token: &str| match jsonwebtoken::decode::<Jwt>(
                token,
                &decoding_key,
                &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256),
            ) {
                Ok(_) => Ok(Validation::Valid),
                Err(error) => Ok(Validation::Invalid(error.into())),
            };

            let valid_token = match Editor::new(&format!("token for {}", selected_profile.env))
                .with_validator(validator)
                .prompt()
            {
                Ok(ok) => ok,
                Err(InquireError::OperationCanceled) => break,
                Err(InquireError::OperationInterrupted) => std::process::exit(0),
                _ => todo!(),
            };

            env_data.insert(selected_profile.env.clone(), valid_token);
            // TODO print when token expires
        }

        let full_path_with_method = format!("{} {}", selected_operation.method, full_path);

        if let Method::GET = selected_operation.method {
        } else {
            match Editor::new("body")
                .with_predefined_text(data.get(&full_path_with_method).unwrap_or(&String::new()))
                .with_file_extension(".json")
                .prompt()
            {
                Ok(ok) => {
                    if !ok.is_empty() {
                        data.insert(full_path_with_method.to_owned(), ok.to_owned());
                    }
                }
                Err(InquireError::OperationCanceled) => break,
                Err(InquireError::OperationInterrupted) => std::process::exit(0),
                _ => todo!(),
            };
        }

        send_loop(
            selected_profile,
            selected_api,
            selected_operation,
            env_data,
            data,
        );
    }
}

fn send_loop(
    selected_profile: &TicProfile,
    selected_api: &ApiDefinition,
    selected_operation: &TicOperation,
    env_data: &mut HashMap<String, String>,
    data: &mut HashMap<String, String>,
) {
    loop {
        let full_path_with_parameters =
            build_request_path(selected_profile, selected_api, selected_operation, data);
        let full_path_with_method = format!(
            "{} {}",
            selected_operation.method, full_path_with_parameters
        );
        match Text::new(&full_path_with_method).prompt() {
            Ok(_) => (),
            Err(InquireError::OperationCanceled) => break,
            Err(InquireError::OperationInterrupted) => std::process::exit(0),
            _ => todo!(),
        };

        let body: String = data
            .get(&full_path_with_method)
            .unwrap_or(&String::new())
            .to_owned();

        match reqwest::blocking::Client::new()
            .request(
                selected_operation.method.to_owned(),
                &full_path_with_parameters,
            )
            .body(body)
            .header(
                "Authorization",
                format!(
                    "Bearer {}",
                    env_data
                        .get(&selected_profile.env)
                        .unwrap_or(&String::new())
                ),
            )
            .send()
        {
            Ok(response) => {
                let res: String = response
                    .text()
                    .expect("Could not get response text")
                    .chars()
                    .into_iter()
                    .collect();

                const LIMIT: usize = 1000;
                println!("{}", res.chars().take(LIMIT).collect::<String>());
                if res.len() > LIMIT {
                    println!("...");
                }

                let formatted_res = json_formatter(res.clone()).unwrap_or(res);

                match Editor::new("response body")
                    .with_predefined_text(&formatted_res)
                    .with_file_extension(".json")
                    .prompt()
                {
                    Ok(_) => (),
                    Err(InquireError::OperationCanceled) => break,
                    Err(InquireError::OperationInterrupted) => std::process::exit(0),
                    _ => todo!(),
                };
            }
            Err(err) => println!("{}", err),
        }
    }
}
