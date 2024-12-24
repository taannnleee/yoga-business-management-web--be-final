package org.example.yogabusinessmanagementweb.common.entities;
import lombok.*;
import org.example.yogabusinessmanagementweb.common.Enum.MessageType;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ChatMessage {

    private MessageType type;
    private String content;
    private String sender;

}

