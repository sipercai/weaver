package live_check_advice

import rego.v1

allowed_operations := {
	"chat",
	"generate_content",
	"text_completion",
	"embeddings",
	"retrieval",
	"create_agent",
	"invoke_agent",
	"execute_tool",
	"rerank",
	"invoke_workflow",
	"react",
}

provider_required_operations := {
	"chat",
	"generate_content",
	"text_completion",
	"embeddings",
	"create_agent",
	"invoke_agent",
	"rerank",
}

allowed_span_kinds := {
	"LLM",
	"EMBEDDING",
	"RETRIEVER",
	"TOOL",
	"AGENT",
	"RERANKER",
	"ENTRY",
	"STEP",
	"WORKFLOW",
	"MCP",
}

expected_operations_by_kind := {
	"LLM": ["chat", "generate_content", "text_completion"],
	"EMBEDDING": ["embeddings"],
	"RETRIEVER": ["retrieval"],
	"TOOL": ["execute_tool"],
	"MCP": ["execute_tool"],
	"AGENT": ["create_agent", "invoke_agent"],
	"RERANKER": ["rerank"],
	"WORKFLOW": ["invoke_workflow"],
	"STEP": ["react"],
}

skill_attributes := {
	"gen_ai.skill.name",
	"gen_ai.skill.id",
	"gen_ai.skill.description",
	"gen_ai.skill.version",
}

is_genai_span if {
	input.sample.span
	has_attribute("gen_ai.operation.name")
}

is_genai_span if {
	input.sample.span
	has_attribute("gen_ai.span.kind")
}

is_genai_span if {
	input.sample.span
	has_attribute("gen_ai.span_kind_name")
}

is_genai_span if {
	input.sample.span
	has_attribute("gen_ai.provider.name")
}

is_genai_span if {
	input.sample.span
	has_attribute("gen_ai.system")
}

attribute_value(name) := value if {
	some attr in input.sample.span.attributes
	attr.name == name
	value := attr.value
}

has_attribute(name) if {
	some attr in input.sample.span.attributes
	attr.name == name
}

has_loongsuite_span_kind if {
	has_attribute("gen_ai.span.kind")
}

has_loongsuite_span_kind if {
	has_attribute("gen_ai.span_kind_name")
}

loongsuite_span_kind := kind if {
	kind := attribute_value("gen_ai.span.kind")
}

loongsuite_span_kind := kind if {
	not has_attribute("gen_ai.span.kind")
	kind := attribute_value("gen_ai.span_kind_name")
}

entry_span if {
	kind := loongsuite_span_kind
	kind == "ENTRY"
}

array_contains(values, target) if {
	some value in values
	value == target
}

operation_name := op if {
	op := attribute_value("gen_ai.operation.name")
}

has_skill_context if {
	some name in skill_attributes
	has_attribute(name)
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_deprecated_system",
	"advice_level": "violation",
	"advice_context": {"attribute_key": "gen_ai.system", "expected": "gen_ai.provider.name"},
	"message": "LoongSuite GenAI telemetry must use 'gen_ai.provider.name' instead of deprecated 'gen_ai.system'.",
} if {
	input.sample.span
	has_attribute("gen_ai.system")
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_missing_operation_name",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "expected": "gen_ai.operation.name"},
	"message": sprintf("LoongSuite GenAI span '%s' is missing 'gen_ai.operation.name'. ENTRY spans are not required to set an operation name.", [input.sample.span.name]),
} if {
	is_genai_span
	not entry_span
	not has_attribute("gen_ai.operation.name")
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_missing_span_kind",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "expected": "gen_ai.span.kind"},
	"message": sprintf("LoongSuite GenAI span '%s' is missing 'gen_ai.span.kind'. The legacy Alibaba Group key 'gen_ai.span_kind_name' is accepted as a fallback.", [input.sample.span.name]),
} if {
	is_genai_span
	has_attribute("gen_ai.operation.name")
	not has_loongsuite_span_kind
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_unknown_operation_name",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "operation_name": op},
	"message": sprintf("LoongSuite GenAI operation '%s' is not defined in the LoongSuite semantic conventions.", [op]),
} if {
	is_genai_span
	op := operation_name
	op != "rerank_documents"
	not allowed_operations[op]
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_rerank_documents_operation",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "operation_name": "rerank_documents", "expected": "rerank"},
	"message": "LoongSuite rerank spans must use 'gen_ai.operation.name=rerank', not 'rerank_documents'.",
} if {
	is_genai_span
	operation_name == "rerank_documents"
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_unknown_span_kind",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "span_kind": kind},
	"message": sprintf("LoongSuite GenAI span kind '%s' is not defined in the LoongSuite semantic conventions.", [kind]),
} if {
	is_genai_span
	kind := loongsuite_span_kind
	not allowed_span_kinds[kind]
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_span_kind_operation_mismatch",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "span_kind": kind, "operation_name": op, "expected_operations": expected_ops},
	"message": sprintf("LoongSuite GenAI span kind '%s' is not compatible with operation '%s'.", [kind, op]),
} if {
	is_genai_span
	kind := loongsuite_span_kind
	expected_ops := expected_operations_by_kind[kind]
	op := operation_name
	not array_contains(expected_ops, op)
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_missing_provider_name",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "operation_name": op, "expected": "gen_ai.provider.name"},
	"message": sprintf("LoongSuite GenAI operation '%s' requires 'gen_ai.provider.name'.", [op]),
} if {
	is_genai_span
	op := operation_name
	provider_required_operations[op]
	not has_attribute("gen_ai.provider.name")
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_tool_missing_name",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "expected": "gen_ai.tool.name"},
	"message": "LoongSuite tool execution spans must include 'gen_ai.tool.name'.",
} if {
	is_genai_span
	operation_name == "execute_tool"
	not has_attribute("gen_ai.tool.name")
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_tool_skill_missing_name",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "expected": "gen_ai.skill.name"},
	"message": "LoongSuite tool execution spans only require skill attributes when a skill context exists; when present, 'gen_ai.skill.name' is required.",
} if {
	is_genai_span
	operation_name == "execute_tool"
	has_skill_context
	not has_attribute("gen_ai.skill.name")
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_tool_skill_missing_id",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "expected": "gen_ai.skill.id"},
	"message": "LoongSuite tool execution spans only require skill attributes when a skill context exists; when present, 'gen_ai.skill.id' is required.",
} if {
	is_genai_span
	operation_name == "execute_tool"
	has_skill_context
	not has_attribute("gen_ai.skill.id")
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_react_round_missing",
	"advice_level": "improvement",
	"advice_context": {"span_name": input.sample.span.name, "operation_name": "react", "expected": "gen_ai.react.round"},
	"message": "LoongSuite ReAct step spans should include 'gen_ai.react.round' when the framework exposes it.",
} if {
	is_genai_span
	operation_name == "react"
	not has_attribute("gen_ai.react.round")
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_react_finish_reason_missing",
	"advice_level": "improvement",
	"advice_context": {"span_name": input.sample.span.name, "operation_name": "react", "expected": "gen_ai.react.finish_reason"},
	"message": "LoongSuite ReAct step spans should include 'gen_ai.react.finish_reason' when the framework exposes it.",
} if {
	is_genai_span
	operation_name == "react"
	not has_attribute("gen_ai.react.finish_reason")
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_success_status_ok",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "status_code": input.sample.span.status.code, "expected": "unset"},
	"message": "Successful LoongSuite GenAI spans should leave span status unset; status code 'ok' is reserved for explicit application semantics.",
} if {
	is_genai_span
	lower(input.sample.span.status.code) == "ok"
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_finish_reasons_json_string",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "attribute_key": "gen_ai.response.finish_reasons"},
	"message": "'gen_ai.response.finish_reasons' must be emitted as an array value, not as a JSON-encoded string.",
} if {
	is_genai_span
	value := attribute_value("gen_ai.response.finish_reasons")
	is_string(value)
	startswith(value, "[")
}
