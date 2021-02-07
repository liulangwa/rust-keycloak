use blocking::ClientBuilder;
use reqwest::blocking;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug)]
pub struct TokenResponse {
    //skip_serializing_if属性类似golang中的omitempty,值为None时候，序列化为json时候忽略给字段，否则会生成 "access_token":null
    #[serde(skip_serializing_if = "Option::is_none")]
    access_token: Option<String>, //Option在反序列化时候如果不存在该字段则值为None，如果不用Option包裹，会反序列化失败
    expires_in: Option<i64>,
    refresh_expires_in: Option<i64>,
    refresh_token: Option<String>,
    token_type: Option<String>,
    #[serde(rename(serialize = "not-before-policy", deserialize = "not-before-policy"))]
    not_before_policy: Option<i32>,
    session_state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
    scope: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct KeycloakAPIGroup {
    // A set of Access.
    access: HashMap<String, bool>,
    // A set of Attributes.
    attributes: HashMap<String, String>,
    // A set of Client Roles.
    client_roles: HashMap<String, String>,
    // Group ID.
    id: Option<String>,
    name: String,
    // +optional
    path: Option<String>, // A set of Realm Roles.
                          // RealmRoles []string `json:"realmRoles,omitempty"`

                          // A set of subGroups.
                          // +optional
                          // SubGroups []KeycloakAPIGroup `json:"subGroups,omitempty"`
}

impl KeycloakAPIGroup {
    pub fn new(
        access: HashMap<String, bool>,
        attributes: HashMap<String, String>,
        client_roles: HashMap<String, String>,
        id: Option<String>,
        name: String,
        path: Option<String>,
    ) -> Self {
        Self {
            access,
            attributes,
            client_roles,
            id,
            name,
            path,
        }
    }
}

pub struct KeycloadClient {
    base_url: String,
    realm: String,
    username: String,
    passward: String,
    token: RefCell<String>,
}

impl KeycloadClient {
    pub fn new(base_url: String, realm_name: String, username: String, passward: String) -> Self {
        Self {
            base_url: base_url,
            username: username,
            passward: passward,
            token: RefCell::new("".to_string()),
            realm: realm_name,
        }
    }

    pub fn get_auuthenticated_client(&self) -> Result<(), reqwest::Error> {
        let mut form_mut = HashMap::new();
        form_mut.insert("username", self.username.clone());
        form_mut.insert("password", self.passward.clone());
        form_mut.insert("client_id", "admin-cli".to_string());
        form_mut.insert("grant_type", "password".to_string());

        let mut headers = reqwest::header::HeaderMap::new();
        headers.append(
            "Content-Type",
            "application/x-www-form-urlencoded".parse().unwrap(),
        );

        let auth_url = format!(
            "{}/auth/realms/{}/protocol/openid-connect/token",
            self.base_url, self.realm
        );

        let resp = ClientBuilder::new()
            .danger_accept_invalid_certs(true)
            .build()?
            .post(&auth_url)
            .form(&form_mut)
            .headers(headers)
            .send()?;

        let body = resp.text()?;

        println!("resp body {}", &body);

        let token_response_result: Result<TokenResponse, serde_json::Error> =
            serde_json::from_str(&body);

        //debug
        // println!("token_response_result: {:?}", &token_response_result);

        match &token_response_result {
            Ok(_) => (),
            Err(err) => {
                println!("{:?}", err);
                // return Err(reqwest::request(err.to_string()));
            }
        };

        if token_response_result.is_ok() {
            let token_response = token_response_result.unwrap();

            if token_response.error.is_none() {
                self.token
                    .replace(token_response.access_token.clone().unwrap().clone());
                println!("token:{}", token_response.access_token.unwrap())
            }
        }

        println!("self:{:?}", &self.token.borrow());

        Ok(())
    }

    fn create_group(
        &self,
        realm_name: String,
        group: &KeycloakAPIGroup,
    ) -> Result<(), reqwest::Error> {
        let auth_url = format!("{}/auth/admin/realms/{}/groups", self.base_url, realm_name);

        let mut headers = reqwest::header::HeaderMap::new();
        headers.append("Content-Type", "application/json".parse().unwrap());
        headers.append(
            "Authorization",
            format!("Bearer {}", self.token.borrow()).parse().unwrap(),
        );

        let resp = ClientBuilder::new()
            .danger_accept_invalid_certs(true)
            .build()?
            .post(&auth_url)
            .json(group)
            .headers(headers)
            .send()?;

        match resp.status() {
            reqwest::StatusCode::CREATED | reqwest::StatusCode::NO_CONTENT => {
                let location = resp
                    .headers()
                    .get(String::from("Location"))
                    .unwrap()
                    .to_str()
                    .unwrap();
                let pos = location.rfind("/").unwrap();
                let (_, id) = location.split_at(pos + 1);
                println!("success! id:{:?}", id);
            }
            s => println!("Received response status: {:?}", s),
        };

        Ok(())
    }
}

fn main() -> Result<(), reqwest::Error> {
    let keycload_client: KeycloadClient = KeycloadClient::new(
        String::from("https://sso.iam.jdcloud.local"),
        String::from("basic"),
        String::from("xxxx"),
        String::from("xxxxxx"),
    );

    keycload_client.get_auuthenticated_client()?;

    let kcgroup = KeycloakAPIGroup::new(
        HashMap::<String, bool>::new(),
        HashMap::<String, String>::new(),
        HashMap::<String, String>::new(),
        Option::None,
        String::from("rst-group-new"),
        Option::None,
    );

    keycload_client.create_group(String::from("Basic"), &kcgroup)?;

    Ok(())
}
