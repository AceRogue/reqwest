#[cfg(feature = "boring-tls")]
use boring::ssl::SslConnectorBuilder;
#[cfg(feature = "boring-tls")]
use boring::ssl::{SslConnector, SslMethod, SslVersion};
#[cfg(feature = "boring-tls")]
use http::{header, HeaderMap};
mod support;

#[cfg(all(feature = "boring-tls", feature = "__tls"))]
#[tokio::test]
async fn test_boring_tls() {
    let _ = env_logger::try_init();

    let tls =
        reqwest::BoringSslBuilderWrapper::new(std::sync::Arc::new(create_ssl_connector_builder));

    let client = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let res = client
        .get("https://tls.peet.ws/api/clean")
        .send()
        .await
        .unwrap();
    // let res = client.post("https://stockx.com/api/p/e").headers(headers()).body(
    //     "{\"query\":\"query GetSearchResults($filtersVersion: Int, $query: String!, $page: BrowsePageInput, $sort: BrowseSortInput, $staticRanking: BrowseExperimentStaticRankingInput) {\\n  browse(\\n    query: $query\\n    page: $page\\n    sort: $sort\\n    filtersVersion: $filtersVersion\\n    experiments: {staticRanking: $staticRanking}\\n  ) {\\n    categories {\\n      id\\n      name\\n      count\\n    }\\n    results {\\n      edges {\\n        objectId\\n        node {\\n          ... on Product {\\n            id\\n            urlKey\\n            primaryTitle\\n            secondaryTitle\\n            media {\\n              thumbUrl\\n            }\\n            brand\\n            productCategory\\n            ...FavoriteProductFragment\\n          }\\n          ... on Variant {\\n            id\\n            product {\\n              id\\n              urlKey\\n              primaryTitle\\n              secondaryTitle\\n              media {\\n                thumbUrl\\n              }\\n              brand\\n              productCategory\\n            }\\n          }\\n        }\\n      }\\n      pageInfo {\\n        limit\\n        page\\n        pageCount\\n        queryId\\n        queryIndex\\n        total\\n      }\\n    }\\n    sort {\\n      id\\n      order\\n    }\\n  }\\n}\\n\\nfragment FavoriteProductFragment on Product {\\n  favorite\\n}\",\"variables\":{\"filtersVersion\":4,\"query\":\"jordan1\",\"sort\":{\"id\":\"featured\",\"order\":\"DESC\"},\"staticRanking\":{\"enabled\":false},\"page\":{\"index\":1,\"limit\":10}},\"operationName\":\"GetSearchResults\"}"
    // ).send().await.unwrap();

    println!("{}", res.status());
    let body = res.text().await.unwrap();
    println!("{:?}", body);
}

#[cfg(feature = "boring-tls")]
fn headers() -> HeaderMap {
    let mut headers = header::HeaderMap::new();
    headers.insert("authority", "stockx.com".parse().unwrap());
    headers.insert("accept", "application/json".parse().unwrap());
    headers.insert("accept-language", "en-US".parse().unwrap());
    headers.insert("apollographql-client-name", "Iron".parse().unwrap());
    headers.insert(
        "apollographql-client-version",
        "2023.08.20.01".parse().unwrap(),
    );
    headers.insert("app-platform", "Iron".parse().unwrap());
    headers.insert("app-version", "2023.08.20.01".parse().unwrap());
    headers.insert("cache-control", "no-cache".parse().unwrap());
    headers.insert("content-type", "application/json".parse().unwrap());
    // headers.insert(header::COOKIE, "__pxvid=ceee1581-0a9e-11ee-8d49-0242ac120004; stockx_device_id=94cbb3fc-3209-43ac-88c6-69ae4eada325; language_code=en; _pxvid=ceab60df-0a9e-11ee-9c0e-f155a3528292; _gcl_au=1.1.357140422.1689141868; RoktRecogniser=0b87f5fb-e0a8-4dd4-861d-c219dd279279; __pdst=4e659b1cec2b4e579cc677b56a965282; ajs_anonymous_id=2a37d20d-1333-4abb-9239-2ae7875db684; _ga=GA1.1.899087838.1689141867; __ssid=4683114eaed7e4d13a3884c744d5841; rskxRunCookie=0; rCookie=p5a01cuxkeimenuy24f4fljzbgxtr; stockx_dismiss_modal=true; stockx_dismiss_modal_set=2023-07-12T06%3A04%3A54.241Z; stockx_dismiss_modal_expiration=2024-07-12T06%3A04%3A54.241Z; stockx_homepage=sneakers; stockx_session_id=6729ec84-0838-4235-83e6-a8a97087a8b1; stockx_session=5b8e551d-3341-41b0-9807-529a3fad74bc; stockx_selected_region=JP; display_location_selector=false; pxcts=926bad80-4648-11ee-8082-7a507a665249; _gid=GA1.2.735492191.1693298800; _gat=1; OptanonConsent=isGpcEnabled=0&datestamp=Tue+Aug+29+2023+16%3A46%3A40+GMT%2B0800+(%E4%B8%AD%E5%9B%BD%E6%A0%87%E5%87%86%E6%97%B6%E9%97%B4)&version=202211.2.0&isIABGlobal=false&hosts=&consentId=65ef5e00-739b-403e-9daf-674844738150&interactionCount=1&landingPath=https%3A%2F%2Fstockx.com%2F&groups=C0001%3A1%2CC0002%3A1%2CC0004%3A1%2CC0005%3A1%2CC0003%3A1; _px3=e209cf826a1254256bc3280b9db30e94fdb9287364ae76b71c929f928d7c0e47:46SY1tjXsFuc14buhQilq+1Hf6ZK388jNSaIMozpGDM7EbDSPJGTP/rUfi8NhedmXoqUhEmgPrdg1tAJOSeGfA==:1000:mX5JYZ2p0phcDrckLsE1YSy8Sn3uqBrFdCCyHB2DFXOWU/gIz6R3ScYQT6dI3l6Fs3zkMQGuuyOXO/L1WEXxn22B3GgOG0LsV2E/3L3/mFZJvLQYzJ8y2sQZ3JemBCBvIxg9DaueTdVXHGVzaNI+t3ShBwJ7U6YhdVbaYVXedb3WeXdnCKFMK915KFBdN6EEg9CoyFm9DTM/1iMlPM4E5g==; QuantumMetricSessionID=fceb1e7c24261ca1a8eda3fac259a431; QuantumMetricUserID=4fb5ebfa6ea1cdd91696dc3d6102dd48; cf_clearance=2ng2NFa1ZttIh6UIVgbCk9igUpm90bT9twcUBSCCcJI-1693298801-0-1-4ec853b9.a9fd0c70.1ec0fea3-0.2.1693298801; IR_gbd=stockx.com; ftr_blst_1h=1693298804716; _pxde=81e5af207b6a63f7edee96e35fb84656c38b59785ad072568cc6d46babf53f87:eyJ0aW1lc3RhbXAiOjE2OTMyOTg4MDc4NTIsImZfa2IiOjB9; _ga=GA1.1.899087838.1689141867; rbuid=rbos-a41ef1f3-6d71-4978-9127-a5c61af39d56; _pxhd=bMPvKKWCns4V7N-pZZ7HAvhZKqaBpS/Ps3/UsHbT47TSqu6YDNP3qFO5Zc1deLCSEquJCuRbp9BYDFEtdkhOWA==:qvQjgGecm1hK4/rJQ346BHesonq1VH3qQcIu3gzv24ivE3gHJP9eRJSeM/TfgsmkBMdOq/uNBO8FyBmPV6xBAM7L4ttQDUky-ukeOtzp2ig=; forterToken=774ede7132fb47fbadaf7e7ccf34c29d_1693298803757__UDF43-mnf-a4_13ck; _uetsid=97afe8d0464811ee926deb0e1963d37d; _uetvid=f9a87690207911eeb58c2f0d57421ba8; __cf_bm=OFBBMNLmUZpkbG9wVObVP91OAPlH_vTpQOvhFNNqulc-1693298810-0-AWgo+Beh4FdiO098hlMgsO9QPiDurg0Cxgw3Z1D9fi8RIrZaG/LNL7nE8pQWSp/CFVzPc8OXaNnN7v1+V7MNnng=; lastRskxRun=1693298820429; _ga_TYYSNQDG4W=GS1.1.1693298807.2.1.1693298820.0.0.0; IR_9060=1693298813466%7C4294847%7C1693298813466%7C%7C; IR_PI=106cc374-c9ff-11ed-9d0a-872be58c101f%7C1693385213466; _dd_s=rum=0&expire=1693299732435".parse().unwrap());
    headers.insert("dnt", "1".parse().unwrap());
    headers.insert("origin", "https://stockx.com".parse().unwrap());
    headers.insert("pragma", "no-cache".parse().unwrap());
    headers.insert(
        "referer",
        "https://stockx.com/search?s=jordan".parse().unwrap(),
    );
    headers.insert(
        "sec-ch-ua",
        "\"Chromium\";v=\"116\", \"Not)A;Brand\";v=\"24\", \"Google Chrome\";v=\"116\""
            .parse()
            .unwrap(),
    );
    headers.insert("sec-ch-ua-mobile", "?0".parse().unwrap());
    headers.insert("sec-ch-ua-platform", "\"macOS\"".parse().unwrap());
    headers.insert("sec-fetch-dest", "empty".parse().unwrap());
    headers.insert("sec-fetch-mode", "cors".parse().unwrap());
    headers.insert("sec-fetch-site", "same-origin".parse().unwrap());
    headers.insert("selected-country", "JP".parse().unwrap());
    headers.insert("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36".parse().unwrap());
    headers.insert("x-operation-name", "GetSearchResults".parse().unwrap());
    headers.insert(
        "x-stockx-device-id",
        "94cbb3fc-3209-43ac-88c6-69ae4eada325".parse().unwrap(),
    );
    headers.insert(
        "x-stockx-session-id",
        "6729ec84-0838-4235-83e6-a8a97087a8b1".parse().unwrap(),
    );
    headers
}

#[cfg(feature = "boring-tls")]
fn create_ssl_connector_builder() -> SslConnectorBuilder {
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();

    builder.set_grease_enabled(true);
    builder.enable_ocsp_stapling();

    let cipher_list = [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_AES_256_CBC_SHA",
    ];

    builder.set_cipher_list(&cipher_list.join(":")).unwrap();
    let sigalgs_list = [
        "ecdsa_secp256r1_sha256",
        "rsa_pss_rsae_sha256",
        "rsa_pkcs1_sha256",
        "ecdsa_secp384r1_sha384",
        "rsa_pss_rsae_sha384",
        "rsa_pkcs1_sha384",
        "rsa_pss_rsae_sha512",
        "rsa_pkcs1_sha512",
    ];

    builder.set_sigalgs_list(&sigalgs_list.join(":")).unwrap();
    builder.enable_signed_cert_timestamps();
    builder.set_alpn_protos(b"\x02h2\x08http/1.1").unwrap();
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    builder
}
