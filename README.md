### 系统运行步骤：

1. 执行testsrc中的CreateTestWebContent.py文件，生成测试用图片文件。gen_count = 200和pixel_x = pixel_y = 500，表示生成文件的数量与分辨率，可修改。生成的文件夹[TestWebContent]为模拟网站文件，图片中的绿色数字用于标记文件。生成的文件夹[TestWebContentTamper]为模拟篡改用文件，图片中的红色数字用于标记文件。

2. 执行web_tamper_protection.py文件启动服务，会生成快照文件snapshot.json及备份文件夹TestWebContent_back。每次新生成测试网站图片和篡改图片后，需删除快照文件和备份文件夹。由系统重新生成。

3. 防篡改服务启动后，手动复制[TestWebContentTamper]中的文件至[TestWebContent]文件夹。观察日志并查看恢复效果。

4. config中为系统配置文件和日志配置文件。
