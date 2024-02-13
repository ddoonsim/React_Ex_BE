package org.choongang.commons.exceptions;

import org.springframework.http.HttpStatus;

import java.util.Map;
import java.util.List;

public class CommonException extends RuntimeException {

    private HttpStatus status;
    private Map<String, List<String>> messages;

    public CommonException(Map<String, List<String>> messages, HttpStatus status) {
        super();
        this.status = status;
        this.messages = messages;
    }

    public CommonException(String message, HttpStatus status) {
        super(message);
        this.status = status;
    }

    public HttpStatus getStatus() {
        return status;
    }

    public Map<String, List<String>> getMessages() {
        return messages;
    }
}
