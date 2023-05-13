use inquire::{Editor, InquireError, Select, Text};
use openapiv3::{OpenAPI, Operation};
use reqwest::Method;
use serde::Deserialize;
use std::{collections::HashMap, fs};

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
struct TicProfile {
    name: String,
    protocol: String,
    tld: String,
    #[allow(dead_code)]
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
    let config_string =
        fs::read_to_string(".tic-config.json").expect("Could not read configuration file");

    let config: TicConfig =
        serde_json::from_str(&config_string).expect("Could not parse configuration file");

    let apis: Vec<ApiDefinition> = config
        .apis
        .iter()
        .map(|TicApiPath { domain, path }| ApiDefinition {
            domain: domain.to_owned(),
            open_api: read_openapi_from_path_with_removed_security_schemes(path),
        })
        .collect();

    select_profile_loop(config, apis);
}

fn select_profile_loop(config: TicConfig, apis: Vec<ApiDefinition>) {
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

        select_api_loop(selected_profile, &apis);
    }
}

fn select_api_loop(selected_profile: &TicProfile, apis: &[ApiDefinition]) {
    let mut ctx = std::collections::HashMap::<String, String>::new(); // TODO load persisted
                                                                      // env/data into the ctx
                                                                      // from defined environment
                                                                      // by the profile
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

        select_operation_loop(&mut ctx, operations, selected_api, selected_profile);
    }
}

fn select_operation_loop(
    ctx: &mut HashMap<String, String>,
    operations: Vec<TicOperation>,
    selected_api: &ApiDefinition,
    selected_profile: &TicProfile,
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
        // TODO Get saved data for this request

        request_loop(ctx, selected_api, selected_profile, selected_operation);
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
    ctx: &mut HashMap<String, String>,
    selected_api: &ApiDefinition,
    selected_profile: &TicProfile,
    selected_operation: &TicOperation,
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
            .map(|parameter| {
                let param_name = &parameter.parameter_data_ref().name.to_owned();
                match Text::new(&format_parameter_name(parameter)) // TODO search for options in the environment and use as autocomplete
                    .with_initial_value(ctx.get(&param_name.to_owned()).unwrap_or(&"".to_owned()))
                    .prompt()
                {
                    Ok(ok) => {
                        if !ok.is_empty() {
                            ctx.insert(param_name.to_owned(), ok.to_owned());
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

        // TODO set url and query parameters

        // TODO check token expiry and remove from ctx
        // let a = jsonwebtoken::decode_header(token).unwrap();
        if ctx.get("TOKEN").is_none() {
            let token = match Text::new(&format!("token for {}", selected_profile.env)).prompt() {
                Ok(ok) => ok,
                Err(InquireError::OperationCanceled) => break,
                Err(InquireError::OperationInterrupted) => std::process::exit(0),
                _ => todo!(),
            };
            // TODO validate it with environment pem
            if token.len() > 0 {
                ctx.insert("TOKEN".to_owned(), token.to_owned());
            }
        }

        // TODO use body
        let _body = match Editor::new("edit body").prompt() {
            Ok(ok) => ok, // TODO use editor
            Err(InquireError::OperationCanceled) => break,
            Err(InquireError::OperationInterrupted) => std::process::exit(0),
            _ => todo!(),
        };

        send_loop(ctx, selected_api, selected_profile, selected_operation);
    }
}

fn send_loop(
    ctx: &mut HashMap<String, String>,
    selected_api: &ApiDefinition,
    selected_profile: &TicProfile,
    selected_operation: &TicOperation,
) {
    loop {
        // TODO insert parameters
        let full_path = format!(
            "{}://{}{}{}",
            selected_profile.protocol,
            selected_api.domain,
            selected_profile.tld,
            selected_operation.path
        );
        let full_path_with_method = format!("{} {}", selected_operation.method, full_path);
        match Text::new(&full_path_with_method).prompt() {
            Ok(_) => (),
            Err(InquireError::OperationCanceled) => break,
            Err(InquireError::OperationInterrupted) => std::process::exit(0),
            _ => todo!(),
        };

        match reqwest::blocking::Client::new()
            .request(selected_operation.method.to_owned(), &full_path)
            // .body(body) // TODO use body
            .header(
                "Authorization",
                format!("Bearer {}", ctx.get("TOKEN").unwrap()),
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

                const LIMIT: usize = 400;
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
