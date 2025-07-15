import hashlib
import json
import os
import platform
import random
import shutil
import subprocess
import threading
import time

from cryptography.fernet import Fernet

from logger import logger


class BackupManager:
    """备份管理系统"""

    def __init__(self, protector, config):
        self.protector = protector
        self.config = config
        self.backup_dir = self.config.get('back.backup_dir')
        self.web_dir = self.config.get('base.web_dir')
        self.encryption_key = None
        self.initialized = False
        self.backup_lock = threading.Lock()

    def initialize_backup_system(self):
        """初始化备份系统"""
        if self.initialized:
            return True

        try:
            if self.config.get('back.enable_backup_encryption', False):
                self.encryption_key = self._load_or_generate_key()

            # 创建备份目录
            self._create_backup_directory()

            # 验证存储空间
            if not self._check_storage_space():
                raise RuntimeError("存储空间不足")

            # 执行初始备份
            self.perform_full_backup()

            # 验证备份完整性
            if not self._validate_backup_integrity():
                raise RuntimeError("初始备份验证失败")

            # 设置安全权限
            self._set_secure_permissions()

            self.initialized = True
            logger.info("备份系统初始化完成")
            return True
        except Exception as e:
            logger.critical(f"备份系统初始化失败: {str(e)}")
            self.protector.alert.alert("备份系统初始化失败", "严重错误")
            return False

    def _create_backup_directory(self):
        """创建备份目录结构"""
        # 创建主备份目录
        if not os.path.exists(self.backup_dir):
            os.makedirs(self.backup_dir, exist_ok=True)
            logger.info(f"创建备份目录: {self.backup_dir}")

        # 创建子目录结构
        required_dirs = [
            "latest",  # 最新备份
            "crypto",  # 加密存储
            "metadata"  # 备份元数据
        ]

        for subdir in required_dirs:
            dir_path = os.path.join(self.backup_dir, subdir)
            if not os.path.exists(dir_path):
                os.makedirs(dir_path, exist_ok=True)
                logger.info(f"创建备份子目录: {subdir}")

    def _set_secure_permissions(self):

        user = self.config.get('back.backup_user', 'root')
        group = self.config.get('back.backup_group', user)

        """设置备份目录安全权限"""
        if platform.system() == "Windows":
            # Windows权限设置
            try:
                subprocess.run([
                    'icacls', self.backup_dir,
                    '/inheritance:r',
                    '/grant:r', f'{user}:(OI)(CI)F',
                    '/grant:r', f'{group}:(OI)(CI)F',
                    '/remove', 'Everyone'
                ], check=True)
                logger.info(f"设置Windows权限: {self.backup_dir}")
            except Exception as e:
                logger.error(f"Windows权限设置失败: {str(e)}")
        else:
            # Linux/Unix权限设置
            try:
                # 设置目录权限 (rwx------)
                os.chmod(self.backup_dir, 0o700)

                # 设置所有权
                if 'back.backup_user' in self.config:

                    # 获取用户UID和GID
                    try:
                        import pwd, grp
                        uid = pwd.getpwnam(user).pw_uid
                        gid = grp.getgrnam(group).gr_gid
                        os.chown(self.backup_dir, uid, gid)
                        logger.info(f"设置备份目录所有权: {user}:{group}")
                    except:
                        logger.warning("无法设置所有权，可能需要root权限")

                logger.info(f"设置Unix权限: {oct(os.stat(self.backup_dir).st_mode)[-3:]}")
            except Exception as e:
                logger.error(f"Unix权限设置失败: {str(e)}")

    def _check_storage_space(self):
        """检查备份存储空间"""
        try:
            # 获取备份目录所在磁盘空间
            disk_usage = shutil.disk_usage(self.backup_dir)
            free_space = disk_usage.free  # 字节

            # 获取网站目录大小
            web_size = self._get_directory_size(self.web_dir)

            # 所需空间 = 网站大小 * 安全系数
            required_space = web_size * self.config.get('back.backup_space_factor', 2.0)

            if free_space < required_space:
                logger.error(
                    f"存储空间不足: 可用空间 {free_space / 1024 ** 2:.2f} MB, "
                    f"需要 {required_space / 1024 ** 2:.2f} MB"
                )
                return False

            logger.info(
                f"存储空间充足: 可用 {free_space / 1024 ** 2:.2f} MB, "
                f"需要 {required_space / 1024 ** 2:.2f} MB"
            )
            return True
        except Exception as e:
            logger.error(f"存储空间检查失败: {str(e)}")
            return False

    def _get_directory_size(self, path):
        """计算目录大小"""
        total = 0
        for dirpath, _, filenames in os.walk(path):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                try:
                    total += os.path.getsize(fp)
                except:
                    continue
        return total

    def _load_or_generate_key(self):
        """加载或生成加密密钥"""
        key_file = os.path.join(self.backup_dir, "crypto", "encryption.key")

        if os.path.exists(key_file):
            try:
                with open(key_file, "rb") as f:
                    key = f.read()
                logger.info("加载现有加密密钥")
                return key
            except Exception as e:
                logger.error(f"加载加密密钥失败: {str(e)}")

        # 生成新密钥
        key = Fernet.generate_key()

        try:
            # 安全存储密钥
            os.makedirs(os.path.dirname(key_file), exist_ok=True)
            with open(key_file, "wb") as f:
                f.write(key)

            # 设置严格权限
            if platform.system() != "Windows":
                os.chmod(key_file, 0o400)

            logger.info("生成并保存新加密密钥")
            return key
        except Exception as e:
            logger.critical(f"无法保存加密密钥: {str(e)}")
            return None

    def perform_full_backup(self):
        """执行全量备份"""
        logger.info("开始全量备份...")
        start_time = time.time()
        #backup_version = f"v{int(time.time())}"
        latest_dir = os.path.join(self.backup_dir, "latest")

        try:
            # 创建版本目录
            os.makedirs(latest_dir, exist_ok=True)

            # 复制文件
            copied_files = 0
            for root, _, files in os.walk(self.web_dir):
                # 计算相对路径
                rel_path = os.path.relpath(root, self.web_dir)
                backup_path = os.path.join(latest_dir, rel_path)

                # 创建目标目录
                if not os.path.exists(backup_path):
                    os.makedirs(backup_path, exist_ok=True)

                for file in files:
                    src_file = os.path.join(root, file)
                    dest_file = os.path.join(backup_path, file)

                    # 复制文件
                    try:
                        # 加密文件
                        if self.config.get('back.enable_backup_encryption', False):
                            self._encrypt_and_copy(src_file, dest_file)
                        else:
                            shutil.copy2(src_file, dest_file)

                        copied_files += 1
                        if copied_files % 100 == 0:
                            logger.debug(f"已备份 {copied_files} 文件...")
                    except Exception as e:
                        logger.error(f"备份文件失败: {src_file} -> {dest_file}: {str(e)}")

            # 创建备份元数据
            self._create_backup_metadata(latest_dir, 'v1')

            # # 更新最新备份链接
            # latest_link = os.path.join(self.backup_dir, "latest")
            # if os.path.exists(latest_link):
            #     os.remove(latest_link)
            # os.symlink(latest_dir, latest_link)

            elapsed = time.time() - start_time
            logger.info(
                f"全量备份完成: {copied_files} 文件, "
                f"耗时 {elapsed:.2f} 秒, "
                # f"版本: {backup_version}"
            )
            return True
        except Exception as e:
            logger.critical(f"全量备份失败: {str(e)}")
            return False

    def _encrypt_and_copy(self, src, dest):
        """加密并复制文件"""
        # 读取源文件
        with open(src, "rb") as f:
            data = f.read()

        # 加密数据
        fernet = Fernet(self.encryption_key)
        encrypted_data = fernet.encrypt(data)

        # 写入目标文件
        with open(dest, "wb") as f:
            f.write(encrypted_data)

        # 保留元数据
        shutil.copystat(src, dest)

    def _create_backup_metadata(self, version_dir, version_id):
        """创建备份元数据"""
        metadata = {
            "version": version_id,
            "timestamp": time.time(),
            "source": self.web_dir,
            "file_count": 0,
            "total_size": 0,
            "files": {}
        }

        # 计算文件哈希和大小
        for root, _, files in os.walk(version_dir):
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, version_dir)

                try:
                    file_size = os.path.getsize(file_path)
                    file_hash = self._calculate_file_hash(file_path)

                    metadata["files"][rel_path] = {
                        "size": file_size,
                        "hash": file_hash,
                        "mtime": os.path.getmtime(file_path)
                    }
                    metadata["file_count"] += 1
                    metadata["total_size"] += file_size
                except Exception as e:
                    logger.error(f"创建元数据失败: {file_path} - {str(e)}")

        # 保存元数据
        meta_file = os.path.join(self.backup_dir, "metadata", f"{version_id}.json")
        with open(meta_file, "w") as f:
            json.dump(metadata, f, indent=2)

        logger.info(f"备份元数据保存到: {meta_file}")

    def _calculate_file_hash(self, file_path):
        """计算文件哈希"""
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def _validate_backup_integrity(self):
        """验证备份完整性"""
        try:
            # 获取最新备份
            latest_dir = os.path.join(self.backup_dir, "latest")
            if not os.path.exists(latest_dir):
                return False

            # latest_backup = os.readlink(latest_dir)
            # version_id = os.path.basename(latest_backup)

            # # 加载元数据
            meta_file = os.path.join(self.backup_dir, "metadata", "v1.json")
            if not os.path.exists(meta_file):
                return False

            with open(meta_file, "r") as f:
                metadata = json.load(f)

            # 验证文件数量和大小
            actual_file_count = 0
            actual_total_size = 0

            for root, _, files in os.walk(latest_dir):
                actual_file_count += len(files)
                for file in files:
                    file_path = os.path.join(root, file)
                    actual_total_size += os.path.getsize(file_path)

            if actual_file_count != metadata["file_count"]:
                logger.error(
                    f"备份文件数量不匹配: "
                    f"元数据 {metadata['file_count']}, "
                    f"实际 {actual_file_count}"
                )
                return False

            if actual_total_size != metadata["total_size"]:
                logger.error(
                    f"备份总大小不匹配: "
                    f"元数据 {metadata['total_size']}, "
                    f"实际 {actual_total_size}"
                )
                return False

            # 抽样验证文件哈希
            sample_files = list(metadata["files"].keys())
            if len(sample_files) > 100:
                sample_files = random.sample(sample_files, 100)

            for rel_path in sample_files:
                file_path = os.path.join(latest_dir, rel_path)
                expected_hash = metadata["files"][rel_path]["hash"]
                actual_hash = self._calculate_file_hash(file_path)

                if expected_hash != actual_hash:
                    logger.error(
                        f"文件哈希不匹配: {rel_path}\n"
                        f"预期: {expected_hash}\n"
                        f"实际: {actual_hash}"
                    )
                    return False

            logger.info("备份完整性验证通过")
            return True
        except Exception as e:
            logger.error(f"备份验证失败: {str(e)}")
            return False

    def recover_file(self, rel_path, target_path):
        """从备份恢复文件"""
        # 获取最新备份路径
        latest_dir = os.path.join(self.backup_dir, "latest")
        if not os.path.exists(latest_dir):
            logger.error("找不到最新备份")
            return False

        src_path = os.path.join(latest_dir, rel_path)

        if not os.path.exists(src_path):
            logger.error(f"备份中找不到文件: {rel_path}")
            return False

        try:
            # 创建目标目录
            os.makedirs(os.path.dirname(target_path), exist_ok=True)

            # 复制文件
            if self.config.get('enable_backup_encryption', False):
                self._decrypt_and_copy(src_path, target_path)
            else:
                shutil.copy2(src_path, target_path)

            logger.info(f"文件恢复成功: {rel_path}")
            return True
        except Exception as e:
            logger.error(f"文件恢复失败: {rel_path} - {str(e)}")
            return False

    def _decrypt_and_copy(self, src, dest):
        """解密并复制文件"""
        # 读取加密文件
        with open(src, "rb") as f:
            encrypted_data = f.read()

        # 解密数据
        fernet = Fernet(self.encryption_key)
        try:
            data = fernet.decrypt(encrypted_data)
        except:
            logger.error("文件解密失败 - 可能密钥不匹配")
            raise

        # 写入目标文件
        with open(dest, "wb") as f:
            f.write(data)

        # 保留元数据
        shutil.copystat(src, dest)
