package com.vestri.dynamic;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

record LifecycleRequest(String action, String template, UUID requestId, UUID instanceId) {
    static LifecycleRequest parse(String[] arguments) {
        if (arguments.length == 1 && arguments[0].equals("templates")) {
            return new LifecycleRequest("templates", "", null, null);
        }
        if (arguments.length < 2 || !List.of("spawn", "delete", "list").contains(arguments[0])) {
            throw new IllegalArgumentException("Invalid command");
        }
        String action = arguments[0];
        List<String> name = new ArrayList<>();
        UUID requestId = null;
        UUID instanceId = null;
        boolean confirmed = false;
        for (int index = 1; index < arguments.length; index++) {
            String argument = arguments[index];
            if (argument.equals("--confirm") && action.equals("delete") && !confirmed) {
                confirmed = true;
            } else if (argument.equals("--request-id") && action.equals("spawn") && requestId == null && index + 1 < arguments.length) {
                requestId = parseUUID(arguments[++index]);
            } else if (argument.equals("--instance") && action.equals("delete") && instanceId == null && index + 1 < arguments.length) {
                instanceId = parseUUID(arguments[++index]);
            } else if (argument.startsWith("--")) {
                throw new IllegalArgumentException("Invalid option");
            } else {
                name.add(argument);
            }
        }
        String template = String.join(" ", name).trim();
        if (template.length() >= 2 && template.startsWith("\"") && template.endsWith("\"")) {
            template = template.substring(1, template.length() - 1).trim();
        }
        if (template.isEmpty() || (action.equals("delete") && !confirmed)) {
            throw new IllegalArgumentException("Template and deletion confirmation are required");
        }
        if (action.equals("spawn") && requestId == null) {
            requestId = UUID.randomUUID();
        }
        return new LifecycleRequest(action, template, requestId, instanceId);
    }

    private static UUID parseUUID(String value) {
        UUID parsed = UUID.fromString(value);
        if (!parsed.toString().equalsIgnoreCase(value)) {
            throw new IllegalArgumentException("Invalid UUID");
        }
        return parsed;
    }
}