use std::borrow::Cow;
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

include!("./src/networking/types/service_query.rs");
include!("./src/networking/types/protocol.rs");

const SERVICES_LIST_PATH: &str = "./services.txt"; // Note: The path might need adjustment

fn main() {
    println!("cargo:rerun-if-changed={SERVICES_LIST_PATH}");

    build_services_phf();

    // Keep the original tauri_build::build() call
    tauri_build::build();
}

fn build_services_phf() {
    let out_path = Path::new(&env::var("OUT_DIR").unwrap()).join("services.rs");
    let mut output = BufWriter::new(File::create(out_path).unwrap());

    let mut services_map = phf_codegen::Map::new();

    let input = BufReader::new(File::open(SERVICES_LIST_PATH).unwrap());
    let mut num_entries = 0;
    for line_res in input.lines() {
        // we want to panic if one of the lines is err...
        let line = line_res.unwrap();
        let mut parts = line.split('\t');
        // we want to panic if one of the service names is invalid
        let val = Cow::Owned(get_valid_service_fmt_const(parts.next().unwrap()));
        // we want to panic if port is not a u16, or protocol is not TCP or UDP
        let key = get_valid_service_query(parts.next().unwrap());
        assert!(parts.next().is_none());
        services_map.entry(key, val);
        num_entries += 1;
    }
    // You might need to adjust this assertion based on your services.txt file
    assert_eq!(num_entries, 12084);

    writeln!(
        &mut output,
        "#[allow(clippy::unreadable_literal)]
\
        static SERVICES: phf::Map<ServiceQuery, Service> = {};",
        services_map.build()
    )
    .unwrap();
}

fn get_valid_service_fmt_const(s: &str) -> String {
    match s.trim() {
        invalid
            if ["", "unknown", "-"].contains(&invalid)
                || !invalid.is_ascii()
                || invalid.starts_with('#')
                || invalid.contains(' ')
                || invalid.contains('?') =>
        {
            panic!("Invalid service name found: {invalid}")
        }
        // You might want to remove or adjust the rustrict part if you don't need it
        #[cfg(debug_assertions)]
        inappropriate
            if rustrict::Censor::from_str(inappropriate)
                .with_trie(&SAFE_WORDS_FOR_SERVICE_NAME)
                .analyze()
                .is(rustrict::Type::INAPPROPRIATE) =>
        {
            panic!("Inappropriate service name found: {inappropriate}")
        }
        name => format!("Service::Name(\"{}\")", name),
    }
}

fn get_valid_service_query(s: &str) -> ServiceQuery {
    let mut parts = s.split('/');
    let port = parts.next().unwrap().parse::<u16>().unwrap();
    let protocol_str = parts.next().unwrap();
    let protocol = match protocol_str {
        "tcp" => Protocol::TCP,
        "udp" => Protocol::UDP,
        invalid => panic!("Invalid protocol found: {invalid}"),
    };
    assert!(parts.next().is_none());
    ServiceQuery(port, protocol)
}

// You might need to copy or adapt the SAFE_WORDS_FOR_SERVICE_NAME and rustrict
// dependency if you keep the inappropriate word check.
// You might need to copy or adapt the SAFE_WORDS_FOR_SERVICE_NAME and rustrict
// dependency if you keep the inappropriate word check.
#[cfg(debug_assertions)]
static SAFE_WORDS_FOR_SERVICE_NAME: std::sync::LazyLock<rustrict::Trie> =
    std::sync::LazyLock::new(|| {
        let mut safe_words = rustrict::Trie::default();
        for word in [
            "npp",
            "emfis-cntl",
            "ardus-cntl",
            "pmip6-cntl",
            "mpp",
            "ipp",
            "vpp",
            "epp",
            "kink",
            "kvm-via-ip",
            "dpp",
            "slinkysearch",
            "alta-ana-lm",
            "vpps-qua",
            "vpps-via",
            "ibm-pps",
            "ppsms",
            "ppsuitemsg",
            "icpps",
            "rap-listen",
            "cadabra-lm",
            "pay-per-view",
            "sixtrak",
            "cvmon",
            "houdini-lm",
            "dic-aida",
            "p2pq",
            "bigbrother",
            "bintec-admin",
            "zymed-zpp",
            "cvmmon",
            "btpp2sectrans",
            "conclave-cpp",     // Corrected
            "btpp2audctr1",     // Corrected
            "tclprodebugger",   // Corrected
            "bintec-capi",      // Corrected
            "bintec-tapi",      // Corrected
            "dicom-iscl",       // Corrected
            "dicom-tls",        // Corrected
            "nmsigport",
            "ppp",
            "tl1-telnet",
            "opcon-xps",
            "netwatcher-mon",
            "netwatcher-db",
            "xnm-ssl",
            "edm-mgr-cntrl",
            "isoft-p2p",
            "must-p2p",
            "p2pgroup",
            "quasar-server",
            "int-rcv-cntrl",
            "faxstfx-port",
            "sunlps-http",
            "fagordnc",
            "p2pcommunity",
            "minger",
            "assuria-slm",
            "wcpp",
            "plcy-net-svcs",
            "assyst-dr",
            "mobile-p2p",
            "assuria-ins",
            "taep-as-svc",
            "nlg-data",
            "dj-ice",
            "x500ms",
            "X11:7",
            "p2p-sip",
            "p4p-portal",
            "bmc-perf-agent",
            "ntz-p2p-storage",
            "citrixupp",
            "freezexservice",
            "p2pevolvenet",
            "papachi-p2p-srv",
            "espeasy-p2p",
            "pim-port",
            "vp2p",
            "dicom",
            "icpp",
            "sauterdongle",
            "vocaltec-hos",
            "BackOrifice",
            "dhanalakshmi",
            "3gpp-w1ap",
            "pmsm-webrctl",
            "bif-p2p",
            "as-servermap",
            "nm-asses-admin",
            "ias-session",
            "smar-se-port1",
            "smar-se-port2",
            "canon-cpp-disc",
            "3gpp-monp",
            "emc-pp-mgmtsvc",
            "3gpp-cbsp",
        ] {
            safe_words.set(word, rustrict::Type::SAFE);
        }
        safe_words
    });