from PIL import Image, ImageDraw, ImageFont
import os
import shutil

gen_count = 200
pixel_x = pixel_y = 500

def gen_test_web_content(out_dir, fill):

    if os.path.exists(out_dir) and os.path.isdir(out_dir):
        shutil.rmtree(out_dir)

    # 创建输出目录
    os.makedirs(out_dir, exist_ok=True)

    # 创建500x500白色背景图像
    image = Image.new('RGB', (pixel_x, pixel_y), 'white')
    draw = ImageDraw.Draw(image)

    try:
        # 尝试加载Arial字体（Windows/Mac通用）
        font = ImageFont.truetype("arial.ttf", gen_count)
    except IOError:
        try:
            # 尝试加载字体（Linux通用）
            font = ImageFont.truetype("DejaVuSans.ttf", gen_count)
        except IOError:
            font = ImageFont.load_default()

    # 生成200个图片
    for i in range(1, gen_count + 1):
        # 创建新图像（重用基础图像）
        img = image.copy()
        draw = ImageDraw.Draw(img)

        # 绘制红色数字
        text = str(i)

        bbox = draw.textbbox((0, 0), text, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]

        # 计算居中位置
        x = (pixel_x - text_width) / 2
        y = (pixel_y - text_height) / 2 - 20  # 微调垂直位置

        draw.text((x, y), text, fill=fill, font=font)

        # 保存为24位位图
        img.save(os.path.join(out_dir, f"number_{i:05d}.bmp"), "BMP")

    print(f"已生成{gen_count}个位图到 {out_dir} 目录")


if __name__ == "__main__":
    output_dir = "../TestWebContent"
    gen_test_web_content(output_dir,(0, 255, 0))

    output_dir = "../TestWebContentTamper"
    gen_test_web_content(output_dir, (255, 0, 0))
