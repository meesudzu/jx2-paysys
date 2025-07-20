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
  `username` varchar(32) NOT NULL default 'test03',
  `secpassword` varchar(64) NOT NULL default 'e8c54b11d35825097bdbfccea0d16079',
  `password` varchar(64) NOT NULL default 'a',
  `rowpass` varchar(32) default 'a',
  `trytocard` int(1) NOT NULL default '0',
  `changepwdret` int(1) NOT NULL default '0',
  `active` int(1) NOT NULL default '1',
  `LockPassword` int(11) NOT NULL default '0',
  `trytohack` int(1) NOT NULL default '0',
  `newlocked` int(1) NOT NULL default '0',
  `locked` int(1) NOT NULL default '0',
  `LastLoginIP` int(11) NOT NULL default '0',
  `PasspodMode` int(11) NOT NULL default '0',
  `email` varchar(64) NOT NULL default 'sgame@sgamevn.com',
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
INSERT INTO account VALUES ('1', 'test', '0e698a8ffc1a0af622c7b4db3cb750cc', '0e698a8ffc1a0af622c7b4db3cb750cc', 'test01', '0', '0', '1', '0', '0', '0', '0', '1761716416', '0', '', '123456780', null, '9999999', null, null, '9999999', '0', '0', '0', '0', '0', '0', '0', '0', '3', '0', '0', '0');
