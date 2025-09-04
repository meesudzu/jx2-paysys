/*
Navicat MySQL Data Transfer

Source Server         : localhost_3306
Source Server Version : 40122
Source Host           : localhost:3306
Source Database       : paysys

Target Server Type    : MYSQL
Target Server Version : 40122
File Encoding         : 65001

Date: 2014-11-14 16:06:39
*/

SET FOREIGN_KEY_CHECKS=0;
-- ----------------------------
-- Table structure for `account`
-- ----------------------------
DROP TABLE IF EXISTS `account`;
CREATE TABLE `account` (
  `id` int(11) NOT NULL auto_increment,
  `username` varchar(32) NOT NULL,
  `secpassword` varchar(64) NOT NULL,
  `password` varchar(64) NOT NULL,
  `rowpass` varchar(32) default '1',
  `trytocard` int(1) NOT NULL default '0',
  `changepwdret` int(1) NOT NULL default '0',
  `active` int(1) NOT NULL default '1',
  `LockPassword` int(11) NOT NULL default '0',
  `trytohack` int(1) NOT NULL default '0',
  `newlocked` int(1) NOT NULL default '0',
  `locked` int(1) NOT NULL default '0',
  `LastLoginIP` int(11) NOT NULL default '0',
  `PasspodMode` int(11) NOT NULL default '0',
  `email` varchar(64) NOT NULL default 'admin@jx2.com',
  `cmnd` int(9) NOT NULL default '123456780',
  `dob` date default NULL,
  `coin` int(20) NOT NULL default '0',
  `dateCreate` int(20) default NULL,
  `lockedTime` datetime default NULL,
  `testcoin` int(11) NOT NULL default '9999999',
  `lockedCoin` int(10) NOT NULL default '0',
  `bklactivenew` int(5) NOT NULL default '0',
  `bklactive` int(5) NOT NULL default '0',
  `nExtpoin1` int(5) NOT NULL default '0',
  `nExtpoin2` int(5) NOT NULL default '0',
  `nExtpoin4` int(5) NOT NULL default '0',
  `nExtpoin5` int(5) NOT NULL default '0',
  `nExtpoin6` int(5) NOT NULL default '0',
  `nExtpoin7` int(5) NOT NULL default '0',
  `scredit` int(10) NOT NULL default '0',
  `nTimeActiveBKL` int(10) NOT NULL default '0',
  `nLockTimeCard` int(15) NOT NULL default '0',
  PRIMARY KEY  (`id`),
  UNIQUE KEY `u` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of account
-- ----------------------------
INSERT INTO account VALUES ('1', 'admin', 'e8c54b11d35825097bdbfccea0d16079', 'c4ca4238a0b923820dcc509a6f75849b', '1', '0', '0', '1', '0', '0', '0', '0', '1761716416', '0', '', '123456780', null, '9999999', null, null, '9999999', '0', '0', '0', '0', '0', '0', '0', '0', '3', '0', '0', '0');

-- Table Names
CREATE TABLE `table_names` (
  `id` int(11) NOT NULL,
  `TABLE_NAME` varchar(255) COLLATE latin1_general_ci NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_general_ci;


INSERT INTO `table_names` (`id`, `TABLE_NAME`) VALUES
(1, 'account');


ALTER TABLE `table_names` ADD PRIMARY KEY (`id`);

ALTER TABLE `table_names` MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=12;
COMMIT;

-- Variables
CREATE TABLE `variables` (
  `id` int(11) NOT NULL,
  `Variable_name` varchar(255) COLLATE latin1_general_ci NOT NULL,
  `VARIABLE_VALUE` text COLLATE latin1_general_ci
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_general_ci;


INSERT INTO `variables` (`id`, `Variable_name`, `VARIABLE_VALUE`) VALUES
(1, 'character_set_connection', 'latin1'),
(2, 'character_set_database', 'latin1');


ALTER TABLE `variables` ADD PRIMARY KEY (`id`);


ALTER TABLE `variables` MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;
COMMIT;
