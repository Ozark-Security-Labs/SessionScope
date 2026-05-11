use sessionscope_model::ScanReport;

pub fn render(_report: &ScanReport) -> String {
    concat!(
        "{\n",
        "  \"version\": \"2.1.0\",\n",
        "  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n",
        "  \"runs\": [\n",
        "    {\n",
        "      \"tool\": {\n",
        "        \"driver\": {\n",
        "          \"name\": \"SessionScope\",\n",
        "          \"rules\": []\n",
        "        }\n",
        "      },\n",
        "      \"results\": []\n",
        "    }\n",
        "  ]\n",
        "}\n"
    )
    .to_string()
}
