use colored::*;
use inquire::{validator::Validation, Editor, InquireError, Select, Text};
use jsonwebtoken::DecodingKey;
use openapiv3::{OpenAPI, Operation};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, env, fs};

fn colorize_json_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "null".bright_black().to_string(),
        serde_json::Value::Bool(b) => b.to_string().purple().to_string(),
        serde_json::Value::Number(n) => n.to_string().purple().to_string(),
        serde_json::Value::String(s) => format!("\"{}\"", s.to_string()).green().to_string(),
        serde_json::Value::Array(arr) => {
            let elements: Vec<String> = arr
                .iter()
                .map(colorize_json_value)
                .map(|e| e.to_string())
                .collect();
            format!("[{}]", elements.join(", ")).to_string()
        }
        serde_json::Value::Object(obj) => {
            let elements: Vec<String> = obj
                .iter()
                .map(|(key, value)| {
                    format!(
                        "{}: {}",
                        format!("\"{}\"", key).yellow().to_string(),
                        colorize_json_value(value)
                    )
                })
                .map(|e| e.to_string())
                .collect();
            format!("{{{}}}", elements.join(", ")).to_string()
        }
    }
}

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
        .unwrap_or_else(|err| panic!("Could not read '{}' openapi file: {}", path, err));

    let mut val: serde_json::Value = serde_json::from_str(&openapi_string)
        .unwrap_or_else(|err| panic!("Could not deserialize '{}' openapi: {}", path, err));

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
                path,
            )
        })
        .remove("securitySchemes");

    let api: OpenAPI = serde_json::from_str(&val.to_string()).unwrap_or_else(|err| {
        panic!(
            "Could not deserialize '{}' openapi to OpenAPI: {}",
            path, err
        )
    });

    api
}

#[derive(Deserialize, Debug)]
struct TicProfileConfig {
    name: String,
    env: Option<String>,
    auth: Option<String>,
    data: Option<String>,
}

#[derive(Deserialize, Debug)]
struct TicEnvConfig {
    name: String,
    protocol: String,
    tld: String,
}

#[derive(Deserialize, Debug)]
struct TicDataConfig {
    name: String,
    path: String,
}

#[derive(Deserialize, Debug)]
struct TicAuthConfig {
    name: String,
    path: Option<String>,
    public_pem_path: String,
}

#[derive(Deserialize, Debug)]
struct TicApiPath {
    path: String,
    domain: String,
}

#[derive(Deserialize, Debug)]
struct TicConfig {
    profile: Vec<TicProfileConfig>,
    env: Vec<TicEnvConfig>,
    data: Vec<TicDataConfig>,
    auth: Vec<TicAuthConfig>,
    api: Vec<TicApiPath>,
}

struct TicSetup {
    protocol: String,
    tld: String,
    decoding_key: DecodingKey,
    auth_name: String,
    auth_data: std::collections::HashMap<String, String>,
    auth_data_path: Option<String>,
    data: std::collections::HashMap<String, String>,
    data_path: Option<String>,
}

impl std::fmt::Debug for TicSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TicSetup {{\n    protocol: {:?}\n    tld: {:?}\n    decoding_key: ???\n    auth_data: {:?}\n    auth_data_path: {:?}\n    data: {:?}\n    data_path: {:?}\n}}",
            self.protocol, self.tld, self.auth_data, self.auth_data_path, self.data, self.data_path
        )
    }
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
    if env::args().any(|arg| arg == "--version") {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return;
    }

    let config_string = fs::read_to_string(".tic-config.json").unwrap_or_else(|_| {
        fs::read_to_string(format!(
            "{}/{}",
            env::var("HOME").expect("Could not resolve home directory to read configuration file"),
            ".tic-config.json"
        ))
        .expect("Could not read configuration file from HOME or current directory")
    });
    #[cfg(debug_assertions)]
    dbg!(&config_string);

    let config: TicConfig =
        serde_json::from_str(&config_string).expect("Could not parse configuration file");
    #[cfg(debug_assertions)]
    dbg!(&config);

    let apis: Vec<ApiDefinition> = config
        .api
        .iter()
        .map(|TicApiPath { path, domain }| ApiDefinition {
            domain: domain.to_owned(),
            open_api: read_openapi_from_path_with_removed_security_schemes(path),
        })
        .collect();

    create_setup_loop(config, apis);
}

fn create_setup_loop(config: TicConfig, apis: Vec<ApiDefinition>) {
    loop {
        // TODO if no profiles are configured, prompt for all parts
        let selected_profile_index = match Select::new(
            "profile",
            config
                .profile
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

        let profile = &config.profile[selected_profile_index];
        #[cfg(debug_assertions)]
        dbg!(&profile);

        let profile_auth = profile
            .auth
            .as_ref()
            .expect("Optional profile auth is not implemented yet");

        let auth = match config.auth.iter().find(|e| e.name.eq(profile_auth)) {
            Some(auth) => auth,
            None => {
                println!(
                    "Could not find auth with name '{}' in configuration specified by profile '{}'",
                    profile_auth, profile.name,
                );
                continue;
            }
        };
        #[cfg(debug_assertions)]
        dbg!(&auth);
        let pem_string = match fs::read_to_string(&auth.public_pem_path) {
            Ok(ok) => ok,
            Err(err) => {
                println!(
                    "Could not read {} pem file {}: {}",
                    auth.name, auth.public_pem_path, err
                );
                continue;
            }
        };
        #[cfg(debug_assertions)]
        dbg!(&pem_string);
        let decoding_key = match jsonwebtoken::DecodingKey::from_rsa_pem(pem_string.as_bytes()) {
            Ok(ok) => ok,
            Err(err) => {
                println!(
                    "Could not deserialize {} pem file {}: {}",
                    auth.name, auth.public_pem_path, err
                );
                continue;
            }
        };
        let mut auth_data = std::collections::HashMap::<String, String>::new();
        if let Some(auth_path) = &auth.path {
            let saved_auth_data_string = match fs::read_to_string(&auth_path) {
                Ok(ok) => ok,
                Err(err) => {
                    println!(
                        "Could not read auth {} data file {}: {}",
                        auth.name, auth_path, err
                    );
                    continue;
                }
            };
            #[cfg(debug_assertions)]
            dbg!(&saved_auth_data_string);
            auth_data = match serde_json::from_str(&saved_auth_data_string) {
                Ok(ok) => ok,
                Err(err) => {
                    println!(
                        "Could not deserialize auth {} data file {}: {}",
                        auth.name, auth_path, err
                    );
                    continue;
                }
            };
        }
        #[cfg(debug_assertions)]
        dbg!(&auth_data);

        let profile_env = profile
            .env
            .as_ref()
            .expect("Optional profile env is not implemented yet");

        let env = match config.env.iter().find(|e| e.name.eq(profile_env)) {
            Some(env) => env,
            None => {
                println!(
                    "Could not find env with name '{}' in configuration specified by profile '{}'",
                    profile_env, profile.name,
                );
                continue;
            }
        };
        #[cfg(debug_assertions)]
        dbg!(&env);

        let mut data = std::collections::HashMap::<String, String>::new();

        let data_path = match &profile.data {
            None => None,
            Some(data_name) => {
                if let Some(data_config) = config.data.iter().find(|e| e.name.eq(data_name)) {
                    let saved_data_string = match fs::read_to_string(&data_config.path) {
                        Ok(ok) => ok,
                        Err(err) => {
                            println!(
                                "Could not read {} data file {}: {}",
                                data_config.name, data_config.path, err
                            );
                            continue;
                        }
                    };
                    let saved_data: HashMap<String, String> =
                        match serde_json::from_str(&saved_data_string) {
                            Ok(ok) => ok,
                            Err(err) => {
                                println!(
                                    "Could not deserialize {} data file {}: {}",
                                    data_config.name, data_config.path, err
                                );
                                continue;
                            }
                        };
                    data = saved_data;
                    Some(data_config.path.to_owned())
                } else {
                    println!(
                        "Could not find data with name '{}' in configuration specified by profile '{}'",
                        data_name, profile.name,
                    );
                    continue;
                }
            }
        };
        #[cfg(debug_assertions)]
        dbg!(&data);

        let mut setup = TicSetup {
            protocol: env.protocol.to_owned(),
            tld: env.tld.to_owned(),
            decoding_key: decoding_key.clone(),
            auth_name: auth.name.to_owned(),
            auth_data: auth_data.clone(),
            auth_data_path: auth.path.clone(),
            data: data.clone(),
            data_path,
        };
        #[cfg(debug_assertions)]
        dbg!(&setup);

        select_api_loop(&mut setup, &apis);
    }
}

fn select_api_loop(setup: &mut TicSetup, apis: &[ApiDefinition]) {
    loop {
        let selected_api_index = match Select::new(
            "api",
            apis.iter()
                .map(|ApiDefinition { open_api, .. }| {
                    format!(
                        "{} {}",
                        open_api.info.title.clone(),
                        open_api.info.version.clone()
                    )
                })
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

        let api = &apis[selected_api_index];

        // TODO do this for all apis at the beginning instead
        let operations: Vec<TicOperation> = api
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

        select_operation_loop(setup, api, operations);
    }
}

fn select_operation_loop(setup: &mut TicSetup, api: &ApiDefinition, operations: Vec<TicOperation>) {
    loop {
        let selected_operation_index = match Select::new(
            "request",
            operations
                .iter()
                .map(|TicOperation { name, .. }| name)
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

        let operation = &operations[selected_operation_index];

        request_loop(setup, api, operation);
    }
}

fn build_request_path(
    setup: &mut TicSetup,
    api: &ApiDefinition,
    operation: &TicOperation,
    use_colored: bool,
) -> String {
    let mut full_path_with_parameters = format!(
        "{}://{}{}{}",
        setup.protocol, api.domain, setup.tld, operation.path
    );

    let mut query_params: Vec<(String, String)> = Vec::new();

    operation
        .operation
        .parameters
        .iter()
        .filter_map(|parameter| parameter.as_item())
        .for_each(|parameter| {
            match parameter {
                openapiv3::Parameter::Path { parameter_data, .. } => {
                    if use_colored {
                        full_path_with_parameters = full_path_with_parameters.replace(
                            &format!("{{{}}}", &parameter_name(parameter)),
                            &setup
                                .data
                                .get(&parameter_data.name)
                                .map(|n| n.green())
                                .unwrap_or_else(|| String::from("<missing>").red())
                                .to_string(),
                        );
                    } else {
                        full_path_with_parameters = full_path_with_parameters.replace(
                            &format!("{{{}}}", &parameter_name(parameter)),
                            setup
                                .data
                                .get(&parameter_data.name)
                                .unwrap_or(&String::from("<missing>")),
                        );
                    }
                }
                openapiv3::Parameter::Query { parameter_data, .. } => {
                    let parameter_value = setup.data.get(&parameter_data.name);
                    if parameter_data.required || parameter_value.is_some() {
                        query_params.push((
                            parameter_data.name.to_owned(),
                            if use_colored {
                                parameter_value
                                    .map(|n| n.green())
                                    .unwrap_or_else(|| String::from("<missing>").red())
                                    .to_string()
                            } else {
                                parameter_value
                                    .unwrap_or(&String::from("<missing>"))
                                    .to_owned()
                            },
                        ));
                    }
                }
                _ => todo!(),
            };
        });

    if query_params.is_empty() {
        return full_path_with_parameters;
    }

    let query_string = query_params
        .iter()
        .map(|(name, value)| format!("{}={}", name, value))
        .collect::<Vec<String>>()
        .join("&");

    format!("{}?{}", full_path_with_parameters, query_string)
}

fn parameter_name(parameter: &openapiv3::Parameter) -> String {
    match parameter {
        openapiv3::Parameter::Path { parameter_data, .. }
        | openapiv3::Parameter::Query { parameter_data, .. } => parameter_data.name.to_owned(),
        _ => todo!(),
    }
}

fn parameter_is_required(parameter: &&openapiv3::Parameter) -> bool {
    match parameter {
        openapiv3::Parameter::Path { parameter_data, .. }
        | openapiv3::Parameter::Query { parameter_data, .. } => parameter_data.required,
        _ => todo!(),
    }
}

fn optional_suffix(required: bool) -> &'static str {
    if required {
        ""
    } else {
        " (optional)"
    }
}

fn format_parameter_name(parameter: &openapiv3::Parameter) -> String {
    match parameter {
        openapiv3::Parameter::Path { parameter_data, .. } => format!(
            "{{{}}}{}",
            parameter_data.name.to_owned(),
            optional_suffix(parameter_data.required),
        ),
        openapiv3::Parameter::Query { parameter_data, .. } => format!(
            "?{}{}",
            parameter_data.name.to_owned(),
            optional_suffix(parameter_data.required),
        ),
        _ => todo!(),
    }
}

fn request_loop(setup: &mut TicSetup, api: &ApiDefinition, operation: &TicOperation) {
    loop {
        let full_path_with_parameters = build_request_path(setup, api, operation, true);
        println!("{} {}", operation.method, full_path_with_parameters);

        // TODO print the current body
        // TODO hide edit body for get requests
        let a = match Select::new(
            "",
            vec![
                "send",
                "edit body",
                "edit required parameters",
                "edit optional parameters",
                "invalidate token",
            ],
        )
        .with_vim_mode(true)
        .prompt()
        {
            Ok(ok) => ok,
            Err(InquireError::OperationCanceled) => break,
            Err(InquireError::OperationInterrupted) => std::process::exit(0),
            _ => todo!(),
        };
        if a == "send" {
            send_request(setup, api, operation);
        } else if a == "invalidate token" {
            setup.auth_data.remove(&setup.auth_name);
            write_auth_data(setup)
        } else {
            let full_path = format!(
                "{}://{}{}{}",
                setup.protocol, api.domain, setup.tld, operation.path
            );
            println!("{} {}", operation.method, full_path);

            if a == "edit body" {
                edit_body(operation, &mut setup.data);
                write_data(setup)
            } else if a == "edit required parameters" {
                edit_parameters(operation, &mut setup.data, parameter_is_required);
                write_data(setup)
            } else if a == "edit optional parameters" {
                edit_parameters(operation, &mut setup.data, |parameter| {
                    !parameter_is_required(parameter)
                });
                write_data(setup)
            }
        }
    }
}

fn write_auth_data(setup: &mut TicSetup) {
    if let Some(file_path) = &setup.auth_data_path {
        let s = serde_json::json!(setup.auth_data);
        fs::write(file_path, s.to_string())
            .unwrap_or_else(|err| panic!("Could not write auth data to {}: {}", file_path, err));
    }
}

fn write_data(setup: &mut TicSetup) {
    if let Some(file_path) = &setup.data_path {
        let s = serde_json::json!(setup.data);
        fs::write(file_path, s.to_string())
            .unwrap_or_else(|err| panic!("Could not write data to {}: {}", file_path, err));
    }
}

fn operation_data_key(operation: &TicOperation) -> String {
    format!("{} {}", operation.method, operation.path)
}

fn edit_body(operation: &TicOperation, data: &mut HashMap<String, String>) {
    match Editor::new("body")
        .with_predefined_text(
            data.get(&operation_data_key(operation))
                .unwrap_or(&String::new()),
        )
        .with_file_extension(".json")
        .prompt()
    {
        Ok(ok) => {
            if !ok.is_empty() {
                data.insert(operation_data_key(operation), ok);
            }
        }
        Err(InquireError::OperationCanceled) => (),
        Err(InquireError::OperationInterrupted) => std::process::exit(0),
        _ => todo!(),
    };
}

fn edit_parameters<P>(operation: &TicOperation, data: &mut HashMap<String, String>, filter: P)
where
    P: Fn(&&openapiv3::Parameter) -> bool,
{
    for parameter in operation
        .operation
        .parameters
        .iter()
        .filter_map(|parameter| parameter.as_item())
        .filter(filter)
    {
        let param_name = &parameter.parameter_data_ref().name.to_owned();
        // TODO search for configured options/data/ids and use fuzzy search and autocomplete
        match Text::new(&format_parameter_name(parameter))
            .with_initial_value(data.get(&param_name.to_owned()).unwrap_or(&"".to_owned()))
            .prompt()
        {
            Ok(ok) => {
                if ok.is_empty() {
                    data.remove(&param_name.to_owned());
                } else {
                    data.insert(param_name.to_owned(), ok.to_owned());
                }
            }
            Err(InquireError::OperationCanceled) => return,
            Err(InquireError::OperationInterrupted) => std::process::exit(0),
            _ => todo!(),
        }
    }
}

fn check_and_edit_token(setup: &mut TicSetup) {
    // TODO make this function return the token instead of just saving it in the auth data
    // -> Result<Option<Token>, Cancel>
    if let Some(token) = setup.auth_data.get(&setup.auth_name.to_owned()) {
        match jsonwebtoken::decode::<Jwt>(
            token,
            &setup.decoding_key,
            &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256),
        ) {
            Ok(_) => (),
            Err(error) => {
                println!(
                    "Removed invalid token for auth '{}': {}",
                    &setup.auth_name, error
                );
                setup.auth_data.remove(&setup.auth_name.to_owned());
            }
        }
    }

    if setup.auth_data.get(&setup.auth_name.to_owned()).is_none() {
        let decoding_key = setup.decoding_key.clone();
        let validator = move |token: &str| match jsonwebtoken::decode::<Jwt>(
            token,
            &decoding_key,
            &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256),
        ) {
            Ok(_) => Ok(Validation::Valid),
            Err(error) => Ok(Validation::Invalid(error.into())),
        };

        // TODO make empty string a valid option to send the request without auth
        // and cancel should not send the request
        let valid_token = match Editor::new(&format!("token for {}", setup.auth_name))
            .with_validator(validator)
            .prompt()
        {
            Ok(ok) => ok,
            Err(InquireError::OperationCanceled) => return,
            Err(InquireError::OperationInterrupted) => std::process::exit(0),
            _ => todo!(),
        };

        setup
            .auth_data
            .insert(setup.auth_name.to_owned(), valid_token);
        // TODO print when token expires
    }

    write_auth_data(setup)
}

fn send_request(setup: &mut TicSetup, api: &ApiDefinition, operation: &TicOperation) {
    // TODO do not send request if this is cancelled
    check_and_edit_token(setup);

    // TODO verify that all required parameters exists

    let body: String = setup
        .data
        .get(&operation_data_key(operation))
        .unwrap_or(&String::new())
        .to_owned();

    let full_path_with_parameters = build_request_path(setup, api, operation, false);

    match reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .request(operation.method.to_owned(), &full_path_with_parameters)
        .body(body)
        .header(
            // TODO do not set auth header if no token
            "Authorization",
            format!(
                "Bearer {}",
                setup
                    .auth_data
                    .get(&setup.auth_name)
                    .unwrap_or(&String::new())
            ),
        )
        .header("Content-Type", "application/json")
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
            let rrr = serde_json::from_str(&res);
            match &rrr {
                Ok(ok) => {
                    let colorized = colorize_json_value(ok);
                    println!("{}", colorized.chars().take(LIMIT).collect::<String>());
                    if res.len() > LIMIT {
                        println!("...");
                    }
                }
                Err(_) => {
                    println!("{}", res.chars().take(LIMIT).collect::<String>());
                    if res.len() > LIMIT {
                        println!("...");
                    }
                }
            }

            let formatted_res = json_formatter(res.clone()).unwrap_or(res);

            match Editor::new("response body")
                .with_predefined_text(&formatted_res)
                .with_file_extension(".json")
                .prompt()
            {
                Ok(_) => (),
                Err(InquireError::OperationCanceled) => (),
                Err(InquireError::OperationInterrupted) => std::process::exit(0),
                _ => todo!(),
            };
        }
        Err(err) => println!("{}", err),
    }
}
