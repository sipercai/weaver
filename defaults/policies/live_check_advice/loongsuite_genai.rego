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
	"rerank_documents",
	"invoke_workflow",
	"react",
	"enter",
}

provider_required_operations := {
	"chat",
	"generate_content",
	"text_completion",
	"embeddings",
	"create_agent",
	"invoke_agent",
	"rerank_documents",
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
	"RERANKER": ["rerank_documents"],
	"WORKFLOW": ["invoke_workflow"],
	"STEP": ["react"],
	"ENTRY": ["enter"],
}

expected_otel_span_kind_by_kind := {
	"LLM": "client",
	"EMBEDDING": "client",
	"RERANKER": "internal",
	"ENTRY": "internal",
}

skill_attributes := {
	"gen_ai.skill.name",
	"gen_ai.skill.id",
	"gen_ai.skill.description",
	"gen_ai.skill.version",
}

message_attributes := {
	"gen_ai.input.messages",
	"gen_ai.output.messages",
}

allowed_message_roles := {
	"system",
	"user",
	"assistant",
	"tool",
}

allowed_message_part_types := {
	"text",
	"reasoning",
	"thinking",
	"tool_call",
	"tool_call_response",
	"blob",
	"base64_blob",
	"file",
	"uri",
	"image",
	"audio",
	"video",
	"other_data",
}

text_message_part_types := {
	"text",
	"reasoning",
	"thinking",
}

allowed_finish_reasons := {
	"content_filter",
	"error",
	"length",
	"stop",
	"tool_calls",
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

rerank_span_name := name if {
	model := attribute_value("gen_ai.request.model")
	name := sprintf("rerank_documents %s", [model])
}

rerank_span_name := "rerank_documents" if {
	not has_attribute("gen_ai.request.model")
}

has_skill_context if {
	some name in skill_attributes
	has_attribute(name)
}

message_value_is_array(attr_name) if {
	value := attribute_value(attr_name)
	is_array(value)
}

message_value_is_array(attr_name) if {
	value := attribute_value(attr_name)
	is_string(value)
	json.is_valid(value)
	messages := json.unmarshal(value)
	is_array(messages)
}

message_array(attr_name) := messages if {
	value := attribute_value(attr_name)
	is_array(value)
	messages := value
}

message_array(attr_name) := messages if {
	value := attribute_value(attr_name)
	is_string(value)
	json.is_valid(value)
	messages := json.unmarshal(value)
	is_array(messages)
}

has_non_null_field(obj, field) if {
	object.get(obj, field, null) != null
}

message_has_payload(message) if {
	has_non_null_field(message, "parts")
}

message_has_payload(message) if {
	has_non_null_field(message, "content")
}

message_has_payload(message) if {
	has_non_null_field(message, "tool_calls")
}

message_tool_call_response_has_payload(part) if {
	has_non_null_field(part, "response")
}

message_tool_call_response_has_payload(part) if {
	has_non_null_field(part, "result")
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
	not allowed_operations[op]
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
	"advice_type": "loongsuite_genai_otel_span_kind_mismatch",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "span_kind": kind, "otel_span_kind": input.sample.span.kind, "expected_otel_span_kind": expected_otel_span_kind},
	"message": sprintf("LoongSuite GenAI span kind '%s' must use OTel span kind '%s', got '%s'.", [kind, expected_otel_span_kind, input.sample.span.kind]),
} if {
	is_genai_span
	kind := loongsuite_span_kind
	expected_otel_span_kind := expected_otel_span_kind_by_kind[kind]
	input.sample.span.kind != expected_otel_span_kind
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_rerank_span_name_mismatch",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "expected_span_name": expected_span_name},
	"message": sprintf("LoongSuite rerank span name must be '%s'.", [expected_span_name]),
} if {
	is_genai_span
	kind := loongsuite_span_kind
	kind == "RERANKER"
	expected_span_name := rerank_span_name
	input.sample.span.name != expected_span_name
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

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_messages_not_array",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "attribute_key": attr_name, "actual_type": type_name(value), "expected": "JSON array or array value"},
	"message": sprintf("'%s' must be an array value or a JSON-encoded array string following the GenAI messages schema.", [attr_name]),
} if {
	is_genai_span
	some attr_name in message_attributes
	has_attribute(attr_name)
	value := attribute_value(attr_name)
	not message_value_is_array(attr_name)
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_message_not_object",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "attribute_key": attr_name, "message_index": message_index, "actual_type": type_name(message), "expected": "object"},
	"message": sprintf("'%s[%v]' must be a message object.", [attr_name, message_index]),
} if {
	is_genai_span
	some attr_name in message_attributes
	messages := message_array(attr_name)
	some message_index
	message := messages[message_index]
	not is_object(message)
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_message_role_missing",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "attribute_key": attr_name, "message_index": message_index, "field": "role", "expected": "string"},
	"message": sprintf("'%s[%v].role' is required and must be a string.", [attr_name, message_index]),
} if {
	is_genai_span
	some attr_name in message_attributes
	messages := message_array(attr_name)
	some message_index
	message := messages[message_index]
	is_object(message)
	role := object.get(message, "role", null)
	not is_string(role)
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_message_role_invalid",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "attribute_key": attr_name, "message_index": message_index, "role": role, "expected_roles": allowed_message_roles},
	"message": sprintf("'%s[%v].role' must be one of system, user, assistant, or tool.", [attr_name, message_index]),
} if {
	is_genai_span
	some attr_name in message_attributes
	messages := message_array(attr_name)
	some message_index
	message := messages[message_index]
	is_object(message)
	role := object.get(message, "role", null)
	is_string(role)
	not allowed_message_roles[role]
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_message_payload_missing",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "attribute_key": attr_name, "message_index": message_index, "expected": "parts, content, or tool_calls"},
	"message": sprintf("'%s[%v]' must include message payload in 'parts', 'content', or 'tool_calls'.", [attr_name, message_index]),
} if {
	is_genai_span
	some attr_name in message_attributes
	messages := message_array(attr_name)
	some message_index
	message := messages[message_index]
	is_object(message)
	not message_has_payload(message)
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_message_content_type_invalid",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "attribute_key": attr_name, "message_index": message_index, "field": "content", "actual_type": type_name(content), "expected": "string, array, or object"},
	"message": sprintf("'%s[%v].content' must be a string, array, or object.", [attr_name, message_index]),
} if {
	is_genai_span
	some attr_name in message_attributes
	messages := message_array(attr_name)
	some message_index
	message := messages[message_index]
	is_object(message)
	content := object.get(message, "content", null)
	content != null
	not is_string(content)
	not is_array(content)
	not is_object(content)
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_message_parts_not_array",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "attribute_key": attr_name, "message_index": message_index, "field": "parts", "actual_type": type_name(parts), "expected": "array"},
	"message": sprintf("'%s[%v].parts' must be an array.", [attr_name, message_index]),
} if {
	is_genai_span
	some attr_name in message_attributes
	messages := message_array(attr_name)
	some message_index
	message := messages[message_index]
	is_object(message)
	parts := object.get(message, "parts", null)
	parts != null
	not is_array(parts)
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_message_tool_calls_not_array",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "attribute_key": attr_name, "message_index": message_index, "field": "tool_calls", "actual_type": type_name(tool_calls), "expected": "array"},
	"message": sprintf("'%s[%v].tool_calls' must be an array when present.", [attr_name, message_index]),
} if {
	is_genai_span
	some attr_name in message_attributes
	messages := message_array(attr_name)
	some message_index
	message := messages[message_index]
	is_object(message)
	tool_calls := object.get(message, "tool_calls", null)
	tool_calls != null
	not is_array(tool_calls)
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_message_tool_call_not_object",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "attribute_key": attr_name, "message_index": message_index, "tool_call_index": tool_call_index, "actual_type": type_name(tool_call), "expected": "object"},
	"message": sprintf("'%s[%v].tool_calls[%v]' must be an object.", [attr_name, message_index, tool_call_index]),
} if {
	is_genai_span
	some attr_name in message_attributes
	messages := message_array(attr_name)
	some message_index
	message := messages[message_index]
	is_object(message)
	tool_calls := object.get(message, "tool_calls", [])
	is_array(tool_calls)
	some tool_call_index
	tool_call := tool_calls[tool_call_index]
	not is_object(tool_call)
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_message_part_not_object",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "attribute_key": attr_name, "message_index": message_index, "part_index": part_index, "actual_type": type_name(part), "expected": "object"},
	"message": sprintf("'%s[%v].parts[%v]' must be a part object.", [attr_name, message_index, part_index]),
} if {
	is_genai_span
	some attr_name in message_attributes
	messages := message_array(attr_name)
	some message_index
	message := messages[message_index]
	is_object(message)
	parts := object.get(message, "parts", [])
	is_array(parts)
	some part_index
	part := parts[part_index]
	not is_object(part)
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_message_part_type_missing",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "attribute_key": attr_name, "message_index": message_index, "part_index": part_index, "field": "type", "expected": "string"},
	"message": sprintf("'%s[%v].parts[%v].type' is required and must be a string.", [attr_name, message_index, part_index]),
} if {
	is_genai_span
	some attr_name in message_attributes
	messages := message_array(attr_name)
	some message_index
	message := messages[message_index]
	is_object(message)
	parts := object.get(message, "parts", [])
	is_array(parts)
	some part_index
	part := parts[part_index]
	is_object(part)
	part_type := object.get(part, "type", null)
	not is_string(part_type)
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_message_part_type_invalid",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "attribute_key": attr_name, "message_index": message_index, "part_index": part_index, "part_type": part_type, "expected_types": allowed_message_part_types},
	"message": sprintf("'%s[%v].parts[%v].type' is not a supported GenAI message part type.", [attr_name, message_index, part_index]),
} if {
	is_genai_span
	some attr_name in message_attributes
	messages := message_array(attr_name)
	some message_index
	message := messages[message_index]
	is_object(message)
	parts := object.get(message, "parts", [])
	is_array(parts)
	some part_index
	part := parts[part_index]
	is_object(part)
	part_type := object.get(part, "type", null)
	is_string(part_type)
	not allowed_message_part_types[part_type]
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_message_text_part_content_missing",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "attribute_key": attr_name, "message_index": message_index, "part_index": part_index, "field": "content", "expected": "string"},
	"message": sprintf("'%s[%v].parts[%v].content' is required and must be a string for text/reasoning parts.", [attr_name, message_index, part_index]),
} if {
	is_genai_span
	some attr_name in message_attributes
	messages := message_array(attr_name)
	some message_index
	message := messages[message_index]
	is_object(message)
	parts := object.get(message, "parts", [])
	is_array(parts)
	some part_index
	part := parts[part_index]
	is_object(part)
	part_type := object.get(part, "type", null)
	text_message_part_types[part_type]
	content := object.get(part, "content", null)
	not is_string(content)
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_message_tool_call_name_missing",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "attribute_key": attr_name, "message_index": message_index, "part_index": part_index, "field": "name", "expected": "string"},
	"message": sprintf("'%s[%v].parts[%v].name' is required and must be a string for tool_call parts.", [attr_name, message_index, part_index]),
} if {
	is_genai_span
	some attr_name in message_attributes
	messages := message_array(attr_name)
	some message_index
	message := messages[message_index]
	is_object(message)
	parts := object.get(message, "parts", [])
	is_array(parts)
	some part_index
	part := parts[part_index]
	is_object(part)
	object.get(part, "type", null) == "tool_call"
	name := object.get(part, "name", null)
	not is_string(name)
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_message_tool_call_arguments_missing",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "attribute_key": attr_name, "message_index": message_index, "part_index": part_index, "field": "arguments"},
	"message": sprintf("'%s[%v].parts[%v].arguments' is required for tool_call parts.", [attr_name, message_index, part_index]),
} if {
	is_genai_span
	some attr_name in message_attributes
	messages := message_array(attr_name)
	some message_index
	message := messages[message_index]
	is_object(message)
	parts := object.get(message, "parts", [])
	is_array(parts)
	some part_index
	part := parts[part_index]
	is_object(part)
	object.get(part, "type", null) == "tool_call"
	not has_non_null_field(part, "arguments")
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_message_tool_call_id_type_invalid",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "attribute_key": attr_name, "message_index": message_index, "part_index": part_index, "field": "id", "actual_type": type_name(id), "expected": "string"},
	"message": sprintf("'%s[%v].parts[%v].id' must be a string when present.", [attr_name, message_index, part_index]),
} if {
	is_genai_span
	some attr_name in message_attributes
	messages := message_array(attr_name)
	some message_index
	message := messages[message_index]
	is_object(message)
	parts := object.get(message, "parts", [])
	is_array(parts)
	some part_index
	part := parts[part_index]
	is_object(part)
	object.get(part, "type", null) == "tool_call"
	id := object.get(part, "id", null)
	id != null
	not is_string(id)
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_message_tool_call_response_payload_missing",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "attribute_key": attr_name, "message_index": message_index, "part_index": part_index, "expected": "response or result"},
	"message": sprintf("'%s[%v].parts[%v]' must include 'response' or 'result' for tool_call_response parts.", [attr_name, message_index, part_index]),
} if {
	is_genai_span
	some attr_name in message_attributes
	messages := message_array(attr_name)
	some message_index
	message := messages[message_index]
	is_object(message)
	parts := object.get(message, "parts", [])
	is_array(parts)
	some part_index
	part := parts[part_index]
	is_object(part)
	object.get(part, "type", null) == "tool_call_response"
	not message_tool_call_response_has_payload(part)
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_message_tool_call_response_id_type_invalid",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "attribute_key": attr_name, "message_index": message_index, "part_index": part_index, "field": "id", "actual_type": type_name(id), "expected": "string"},
	"message": sprintf("'%s[%v].parts[%v].id' must be a string when present.", [attr_name, message_index, part_index]),
} if {
	is_genai_span
	some attr_name in message_attributes
	messages := message_array(attr_name)
	some message_index
	message := messages[message_index]
	is_object(message)
	parts := object.get(message, "parts", [])
	is_array(parts)
	some part_index
	part := parts[part_index]
	is_object(part)
	object.get(part, "type", null) == "tool_call_response"
	id := object.get(part, "id", null)
	id != null
	not is_string(id)
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_output_message_finish_reason_missing",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "attribute_key": "gen_ai.output.messages", "message_index": message_index, "field": "finish_reason", "expected": "string"},
	"message": sprintf("'gen_ai.output.messages[%v].finish_reason' is required and must be a string.", [message_index]),
} if {
	is_genai_span
	messages := message_array("gen_ai.output.messages")
	some message_index
	message := messages[message_index]
	is_object(message)
	finish_reason := object.get(message, "finish_reason", null)
	not is_string(finish_reason)
}

deny contains {
	"type": "advice",
	"advice_type": "loongsuite_genai_output_message_finish_reason_invalid",
	"advice_level": "violation",
	"advice_context": {"span_name": input.sample.span.name, "attribute_key": "gen_ai.output.messages", "message_index": message_index, "finish_reason": finish_reason, "expected_finish_reasons": allowed_finish_reasons},
	"message": sprintf("'gen_ai.output.messages[%v].finish_reason' must be one of content_filter, error, length, stop, or tool_calls.", [message_index]),
} if {
	is_genai_span
	messages := message_array("gen_ai.output.messages")
	some message_index
	message := messages[message_index]
	is_object(message)
	finish_reason := object.get(message, "finish_reason", null)
	is_string(finish_reason)
	not allowed_finish_reasons[finish_reason]
}
