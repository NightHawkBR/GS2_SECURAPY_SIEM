-- SecuraPy Platform · schema MySQL (executado pelo docker-compose na primeira subida)

CREATE TABLE IF NOT EXISTS usuarios (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    nome          VARCHAR(100) NOT NULL,
    email         VARCHAR(150) NOT NULL UNIQUE,
    senha_hash    VARCHAR(255) NOT NULL,
    nivel_acesso  TINYINT      NOT NULL DEFAULT 1,
    criado_em     TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_nivel_acesso CHECK (nivel_acesso BETWEEN 1 AND 5)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
