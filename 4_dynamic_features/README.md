# Android Lightweight Dynamic Feature Extractor

Bộ công cụ Python chạy trên Windows với Android Emulator + ADB, xử lý hàng loạt APK theo chu trình:

`install -> launch -> Monkey stimulation -> collect -> uninstall -> next APK`

Mỗi emulator gắn với một worker riêng. Kết quả gồm `dynamic_features.csv`, checkpoint JSONL và telemetry thô theo SHA-256.

## 1. An toàn bắt buộc

Chỉ chạy trong máy nghiên cứu riêng hoặc máy ảo. Emulator không được đăng nhập tài khoản thật, không chứa dữ liệu thật, không dùng thư mục chia sẻ, không kết nối mạng nội bộ/cơ quan. Ưu tiên mạng NAT cô lập có chặn truy cập LAN; snapshot sạch để phục hồi. Không chạy APK nghi độc hại trên điện thoại thật.

## 2. Yêu cầu

- Windows 10/11, Python 3.10+
- Android Studio, Android SDK Platform-Tools (`adb`)
- Android SDK Build-Tools (`aapt` hoặc `apkanalyzer`) nên có trong `PATH`
- Một hoặc nhiều Android Emulator đã boot, mỗi máy có cấu hình/snapshot giống nhau

Kiểm tra:

```bat
adb devices
python --version
aapt version
```

## 3. Cài đặt

```bat
cd 4_dynamic_features
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## 4. Chạy thử một APK

```bat
python main.py --apk-dir "D:\AndroidDataset\APKs" --output "D:\AndroidDataset\Dynamic" --workers 1 --test-apk "D:\AndroidDataset\APKs\sample.apk"
```

## 5. Chạy hàng loạt

Một emulator:

```bat
python main.py --apk-dir "D:\AndroidDataset\APKs" --output "D:\AndroidDataset\Dynamic" --runtime 20 --workers 1
```

Bốn emulator tự nhận diện:

```bat
python main.py --apk-dir "D:\AndroidDataset\APKs" --output "D:\AndroidDataset\Dynamic" --runtime 20 --workers 4 --resume
```

Chỉ định serial:

```bat
python main.py --apk-dir "D:\AndroidDataset\APKs" --output "D:\AndroidDataset\Dynamic" --workers 4 --serials emulator-5554,emulator-5556,emulator-5558,emulator-5560 --resume
```

## 6. Đầu ra

```text
Dynamic/
  dynamic_features.csv
  processed.jsonl
  failed.jsonl
  raw/<sha256>/
    metadata.json
    samples.json
    logcat.txt
    features.json
```

`processed.jsonl` được ghi ngay sau từng APK nên vẫn giữ checkpoint nếu chương trình dừng. `--resume` bỏ qua mẫu đã có `execution_success=1`. Mẫu lỗi được giữ để phân biệt “không có hành vi” với “không chạy được”.

## 7. Lưu ý phương pháp

- Đây là thuộc tính động vì được quan sát khi APK thực thi. Không lấy permission/intent/import từ Manifest hoặc DEX.
- Không root nên socket và file-system telemetry có thể thiếu trên Android mới. `rx_bytes_delta`, `tx_bytes_delta`, logcat và process/resource vẫn dùng được tùy image/API level.
- Monkey chỉ kích hoạt hành vi giao diện cơ bản; malware trì hoãn, cần đăng nhập, phát hiện emulator hoặc chờ lệnh C2 có thể không bộc lộ.
- Nên dùng cùng API level, RAM/CPU, snapshot và thời gian chạy cho toàn bộ tập dữ liệu.
- Nên chạy lặp một phần mẫu để đo độ ổn định và báo cáo tỷ lệ install/launch/execution thành công.

## 8. Feature chính

CPU/PSS/RSS/heap mean-max, process/thread max, network byte delta, socket snapshot, Activity/Service events, log error/warning, exception, ANR, crash, trạng thái install/launch/execution, thời gian thực tế và số nhóm sự kiện quan sát được.

## 9. Giới hạn hiện tại

`adaptive_stop` có trong cấu hình để mở rộng nhưng phiên bản này dùng thời lượng cố định nhằm đảm bảo tính so sánh giữa các mẫu. DNS/domain đích và file create/delete chính xác cần capture ở gateway/VPN hoặc image có quyền cao hơn; không nên suy diễn các giá trị này từ Manifest vì sẽ biến chúng thành đặc trưng tĩnh.

## 10. Giao diện (GUI)

Bấm đúp `chay_gui.bat`, hoặc gõ `python gui.py`. Không cần tự thêm gì vào PATH: khi khởi động, GUI tìm Android SDK (theo `ANDROID_HOME`, `ANDROID_SDK_ROOT`, rồi `%LOCALAPPDATA%\Android\Sdk`) và thêm `platform-tools` (adb), bản `build-tools` mới nhất (aapt) và `emulator` vào PATH của chính tiến trình. Nếu Python chưa có PyYAML, GUI tự cài một lần.

Khung **Emulator** có danh sách AVD đã tạo trong Android Studio và nút *Bật emulator*; GUI đợi đến khi máy ảo boot xong rồi tự đưa nó vào danh sách thiết bị. Tùy chọn *Không lưu trạng thái khi tắt* chạy emulator với `-no-snapshot-save`, để mẫu chạy trước không để lại dấu vết cho lần bật sau.

Tab **Chạy phân tích**: chọn thư mục APK/output (hoặc một APK chạy thử), chọn emulator (mỗi emulator = 1 worker), chỉnh và lưu `config.yaml`, bấm *Bắt đầu*/*Dừng* (dừng êm: APK đang chạy được hoàn tất và gỡ cài đặt). Tab **Kết quả**: bảng `processed.jsonl`, nhấp đúp để xem toàn bộ thuộc tính và logcat.

## 11. Đọc APK từ ổ đĩa ngoài

Mặc định mỗi APK được **chép một lần** từ `--apk-dir` sang thư mục tạm trên ổ máy (`--staging-dir`, mặc định `%TEMP%\dynextract_staging`), SHA-256 được tính ngay trong lúc chép. Sau đó `adb install`, `aapt` đều dùng bản chép; xong APK thì gỡ app và xóa bản chép rồi mới sang file tiếp theo. Khi chạy nhiều emulator, việc đọc ổ ngoài vẫn tuần tự (mỗi lúc chỉ đọc 1 file).

- `--resume` bỏ qua APK theo **tên file** đã có `execution_success=1`, không còn phải đọc/băm toàn bộ ổ ngoài trước khi chạy.
- Nếu ổ ngoài bị rút giữa chừng, chương trình dừng và vẫn ghi CSV thay vì đánh lỗi toàn bộ APK còn lại.
- `--no-staging` để cài trực tiếp từ ổ ngoài như cũ.
