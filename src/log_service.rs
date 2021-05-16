use reqwest::Client;
use std::collections::HashMap;

#[derive(Clone)]
pub struct LogService {
  client: Client,
  log_service_url: String,
  service_name: String,
}

impl LogService {
  pub fn new(log_service_url: &str, service_name: &str) -> Self {
    LogService {
      client: Client::new(),
      log_service_url: String::from(log_service_url),
      service_name: String::from(service_name),
    }
  }

  pub async fn log(self, msg: &str) {
    let mut map: HashMap<&str, &str> = HashMap::new();

    map.insert("source", &self.service_name);
    map.insert("msg", msg);

    self
      .client
      .post(self.log_service_url)
      .json(&map)
      .send()
      .await;
  }
}
