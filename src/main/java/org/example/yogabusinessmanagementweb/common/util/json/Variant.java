package org.example.yogabusinessmanagementweb.common.util.json;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.FieldDefaults;

import java.util.Map;

@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
@Getter
@Setter
public class Variant {
    Map<String, Map<String, String>> variants;
}
