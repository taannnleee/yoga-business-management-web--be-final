package org.example.yogabusinessmanagementweb.dto.response;

import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;

public class ResponseSuccess extends ResponseEntity<ResponseSuccess.Payload> {
   //PUT PATCH DELETE -- không trả về dữ liệu mà chỉ trả về message
    public ResponseSuccess(HttpStatusCode status, String message) {
        super(new Payload(status.value(), message),status);
    }

    // GET: lấy dữ liệu sau đó trả về dữ liệu
    // POST: tạo mới xong rồi thì trả về id cho client để client tiếp tục thực hiện
    public ResponseSuccess(HttpStatusCode status, String message, Object data) {
        super(new Payload(status.value(), message, data), status);
    }

    public static class Payload {
        private final int status;
        private final String message;
        private Object data;
        public Payload(int status, String message, Object data) {
            this.status = status;
            this.message = message;
            this.data = data;
        }

        public Payload(int status, String message) {
            this.status = status;
            this.message = message;
        }


        public Object getData() {
            return data;
        }

        public int getStatus() {
            return status;
        }

        public String getMessage() {
            return message;
        }
    }
}