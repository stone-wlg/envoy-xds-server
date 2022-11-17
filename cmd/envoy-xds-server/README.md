# usage
```sh
$ go run ./cmd/envoy-xds-server/main.go --configFile ./config.yaml
$ go run ./cmd/envoy-xds-server/main.go --configFile ./1000.yaml
$ go run ./cmd/envoy-xds-server/main.go --configFile ./2000.yaml

$ ./bin/envoy-xds-server --configFile ./config.yaml
$ ./bin/envoy-xds-server --configFile ./1000.yaml
$ ./bin/envoy-xds-server --configFile ./2000.yaml
```

# database
```sql
DROP DATABASE IF EXISTS `fedx-pir-1000`;
CREATE DATABASE IF NOT EXISTS `fedx-pir-1000`;
USE `fedx-pir-1000`;
DROP DATABASE IF EXISTS `fedx-pir-2000`;
CREATE DATABASE IF NOT EXISTS `fedx-pir-2000`;
USE `fedx-pir-2000`;
DROP DATABASE IF EXISTS `fedx-pir-3000`;
CREATE DATABASE IF NOT EXISTS `fedx-pir-3000`;
USE `fedx-pir-3000`;

#DROP TABLE IF EXISTS `peer`;
CREATE TABLE IF NOT EXISTS `peer`  (
  `id` BIGINT NOT NULL,
  `party_id` VARCHAR(255) NOT NULL,
  `type` ENUM('pir','xxx') NOT NULL DEFAULT 'pir',
  `host` VARCHAR(255) NOT NULL DEFAULT '0.0.0.0',
  `port` INT NOT NULL DEFAULT 10000,
  `is_deleted` BOOLEAN NOT NULL DEFAULT FALSE
);

#DROP TABLE IF EXISTS `service`;
CREATE TABLE IF NOT EXISTS `service`  (
  `id` BIGINT NOT NULL,
  `party_id` VARCHAR(255) NOT NULL,
  `type` ENUM('pir','xxx') NOT NULL DEFAULT 'pir',
  `host` VARCHAR(255) NOT NULL DEFAULT '0.0.0.0',
  `port` INT NOT NULL DEFAULT 10000,
  `is_deleted` BOOLEAN NOT NULL DEFAULT FALSE
);

INSERT INTO `fedx-pir-1000`.`peer` VALUES (10, '1000', 'pir', '192.168.10.10', 31008, FALSE);
INSERT INTO `fedx-pir-1000`.`peer` VALUES (20, '2000', 'pir', '192.168.10.10', 32008, FALSE);
INSERT INTO `fedx-pir-1000`.`peer` VALUES (30, '3000', 'pir', '192.168.10.10', 33008, FALSE);

INSERT INTO `fedx-pir-2000`.`peer` VALUES (10, '1000', 'pir', '192.168.10.10', 31008, FALSE);
INSERT INTO `fedx-pir-2000`.`peer` VALUES (20, '2000', 'pir', '192.168.10.10', 32008, FALSE);
INSERT INTO `fedx-pir-2000`.`peer` VALUES (30, '3000', 'pir', '192.168.10.10', 33008, FALSE);

INSERT INTO `fedx-pir-3000`.`peer` VALUES (10, '1000', 'pir', '192.168.10.10', 31008, FALSE);
INSERT INTO `fedx-pir-3000`.`peer` VALUES (20, '2000', 'pir', '192.168.10.10', 32008, FALSE);
INSERT INTO `fedx-pir-3000`.`peer` VALUES (30, '3000', 'pir', '192.168.10.10', 33008, FALSE);

INSERT INTO `fedx-pir-1000`.`service` VALUES (11, '1000', 'pir', 'fedx-pir-101-sender-1000-shard-001', 12121, FALSE);
INSERT INTO `fedx-pir-1000`.`service` VALUES (12, '1000', 'pir', 'fedx-pir-101-sender-1000-shard-002', 12122, FALSE);
INSERT INTO `fedx-pir-1000`.`service` VALUES (13, '1000', 'pir', 'fedx-pir-101-sender-1000-shard-003', 12123, FALSE);
INSERT INTO `fedx-pir-1000`.`service` VALUES (14, '2000', 'pir', 'fedx-pir-201-sender-2000-shard-001', 20001, FALSE);
INSERT INTO `fedx-pir-1000`.`service` VALUES (15, '2000', 'pir', 'fedx-pir-201-sender-2000-shard-002', 20002, FALSE);
INSERT INTO `fedx-pir-1000`.`service` VALUES (16, '2000', 'pir', 'fedx-pir-201-sender-2000-shard-003', 20003, FALSE);
INSERT INTO `fedx-pir-1000`.`service` VALUES (17, '3000', 'pir', 'fedx-pir-301-sender-3000-shard-001', 30001, FALSE);
INSERT INTO `fedx-pir-1000`.`service` VALUES (18, '3000', 'pir', 'fedx-pir-301-sender-3000-shard-002', 30002, FALSE);
INSERT INTO `fedx-pir-1000`.`service` VALUES (19, '3000', 'pir', 'fedx-pir-301-sender-3000-shard-003', 30003, FALSE);

INSERT INTO `fedx-pir-2000`.`service` VALUES (11, '1000', 'pir', 'fedx-pir-101-sender-1000-shard-001', 10001, FALSE);
INSERT INTO `fedx-pir-2000`.`service` VALUES (12, '1000', 'pir', 'fedx-pir-101-sender-1000-shard-002', 10002, FALSE);
INSERT INTO `fedx-pir-2000`.`service` VALUES (13, '1000', 'pir', 'fedx-pir-101-sender-1000-shard-003', 10003, FALSE);
INSERT INTO `fedx-pir-2000`.`service` VALUES (14, '2000', 'pir', 'fedx-pir-201-sender-2000-shard-001', 12121, FALSE);
INSERT INTO `fedx-pir-2000`.`service` VALUES (15, '2000', 'pir', 'fedx-pir-201-sender-2000-shard-002', 12122, FALSE);
INSERT INTO `fedx-pir-2000`.`service` VALUES (16, '2000', 'pir', 'fedx-pir-201-sender-2000-shard-003', 12123, FALSE);
INSERT INTO `fedx-pir-2000`.`service` VALUES (17, '3000', 'pir', 'fedx-pir-301-sender-3000-shard-001', 30001, FALSE);
INSERT INTO `fedx-pir-2000`.`service` VALUES (18, '3000', 'pir', 'fedx-pir-301-sender-3000-shard-002', 30002, FALSE);
INSERT INTO `fedx-pir-2000`.`service` VALUES (19, '3000', 'pir', 'fedx-pir-301-sender-3000-shard-003', 30003, FALSE);

INSERT INTO `fedx-pir-3000`.`service` VALUES (11, '1000', 'pir', 'fedx-pir-101-sender-1000-shard-001', 10001, FALSE);
INSERT INTO `fedx-pir-3000`.`service` VALUES (12, '1000', 'pir', 'fedx-pir-101-sender-1000-shard-002', 10002, FALSE);
INSERT INTO `fedx-pir-3000`.`service` VALUES (13, '1000', 'pir', 'fedx-pir-101-sender-1000-shard-003', 10003, FALSE);
INSERT INTO `fedx-pir-3000`.`service` VALUES (14, '2000', 'pir', 'fedx-pir-201-sender-2000-shard-001', 20001, FALSE);
INSERT INTO `fedx-pir-3000`.`service` VALUES (15, '2000', 'pir', 'fedx-pir-201-sender-2000-shard-002', 20002, FALSE);
INSERT INTO `fedx-pir-3000`.`service` VALUES (16, '2000', 'pir', 'fedx-pir-201-sender-2000-shard-003', 20003, FALSE);
INSERT INTO `fedx-pir-3000`.`service` VALUES (17, '3000', 'pir', 'fedx-pir-301-sender-3000-shard-001', 12121, FALSE);
INSERT INTO `fedx-pir-3000`.`service` VALUES (18, '3000', 'pir', 'fedx-pir-301-sender-3000-shard-002', 12122, FALSE);
INSERT INTO `fedx-pir-3000`.`service` VALUES (19, '3000', 'pir', 'fedx-pir-301-sender-3000-shard-003', 12123, FALSE);

SELECT * FROM `peer`;
SELECT * FROM `service`;
```