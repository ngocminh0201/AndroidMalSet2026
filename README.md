# AndroidMalSet2026

Source code of the tools used to build **AndroidMalSet2026**, a dataset of 120,123 labelled Android applications (Benign and four malware categories: Riskware, Adware, SMS malware, Banking malware) described by 20,032 static features and 30 dynamic features.

The repository follows the five-step construction process described in the paper:

1. sample collection,
2. labelling,
3. feature extraction,
4. documentation and release,
5. dataset evaluation.

It contains the code for steps 1 to 3, which produce the dataset files, and a converter that exports the feature matrix to the formats used by common machine learning tools. The machine learning code used for the evaluation in step 5 is not included. The dataset itself (feature matrix, vocabulary, labels and raw feature records) is not stored here; it is available from the authors on request.

Every tool identifies a sample by the SHA-256 hash of its APK file. All intermediate results (labels, raw feature records, vectors) are keyed by this hash, so the steps can be run independently, re-run without reprocessing samples that are already done, and extended with new samples later.

> Comments, log messages and command-line options inside the scripts are written in Vietnamese without diacritics. The options are listed below with their meaning in English.

## Repository layout

```
AndroidMalSet2026/
├── 1_collection/
│   ├── androzoo/
│   │   ├── chuan_bi_danh_muc.py    build a filtered candidate index from the AndroZoo list
│   │   ├── tai_androzoo.py         download APKs from AndroZoo and verify SHA-256
│   │   └── doi_soat_androzoo.py    reconcile the APK folder, the index and the result sheet
│   └── github/
│       ├── thu_gom_github_apk.py   clone GitHub sample repositories and extract APKs
│       ├── thu_gom_tu_zip.py       extract APKs from repositories already downloaded as ZIP
│       ├── ghi_ket_qua.py          shared helper that writes the collection sheet
│       └── github_sources.csv      the 16 GitHub repositories used in the paper
├── 2_labelling/
│   ├── quet_virustotal.py          look up each APK on VirusTotal by SHA-256 (stage 1)
│   └── gan_nhan_gemini.py          assign the final label with Gemini (stage 2)
├── 3_static_features/
│   └── trich_xuat_tinh.py          static feature extraction and vectorisation
├── 4_dynamic_features/
│   ├── main.py                     entry point, one worker per Android emulator
│   ├── runner.py                   install, launch, exercise and observe one APK
│   ├── adb.py                      thin wrapper around ADB
│   ├── collectors.py               CPU, memory, process, network and logcat sampling
│   ├── features.py                 turns the samples into the 30 dynamic features
│   ├── config.py, config.yaml      run settings (observation time, Monkey events...)
│   └── test_features.py            unit test for the feature summary
├── 5_export_formats/
│   ├── chuyen_dinh_dang.py         export the feature matrix to ARFF, LibSVM and NPZ
│   └── vi_du_su_dung.ipynb         example: load the NPZ files with scikit-learn and Keras
├── requirements.txt
└── README.md
```

## Requirements

- Python 3.10 or newer (the dynamic tool was run on Windows; the other tools run on Windows or Linux).
- `pip install -r requirements.txt`
- Step 1: an AndroZoo API key (https://androzoo.uni.lu). `git` is needed for `thu_gom_github_apk.py`.
- Step 2: one or more VirusTotal API keys and a Google Gemini API key.
- Step 4 (dynamic features): Android SDK platform tools (`adb`) and one or more Android emulators that have finished booting.

API keys are read from plain text files placed next to the scripts, one key per line. These files are listed in `.gitignore` and must never be committed:

| Script | Key file | Environment variable |
|---|---|---|
| `tai_androzoo.py` | `api_keys.txt` | option `--key` |
| `quet_virustotal.py` | `api_key.txt` | `VT_API_KEY` |
| `gan_nhan_gemini.py` | `api_key_gemini.txt` | `GEMINI_API_KEY` |

Malware samples are live malicious code. Run the collection and the dynamic analysis only inside an isolated research machine or virtual machine, never on a personal phone.

## Step 1. Sample collection

### AndroZoo

`chuan_bi_danh_muc.py` reads AndroZoo's `latest_with-added-date.csv` (plain or `.gz`) line by line, reads columns by name rather than position, keeps the rows that meet the selection criteria and stores them in a small SQLite index. It is run once, then again whenever a newer list is downloaded.

```
python chuan_bi_danh_muc.py --danh-sach latest_with-added-date.csv --tu-nam 2020 --kich-thuoc 100
```

| Option | Meaning |
|---|---|
| `--danh-sach` | path to the AndroZoo list |
| `--db` | output SQLite index (default `androzoo_index.db`) |
| `--tu-nam` | keep samples added to AndroZoo from this year on |
| `--kich-thuoc` | maximum APK size in MB |
| `--chi-thong-ke` | only print statistics, do not write the index |

`tai_androzoo.py` downloads APKs listed in the index. Files are named by SHA-256; each download is checked against the HTTP status and against the SHA-256 in the index, and a mismatching file is deleted and queued again. The download state is stored in the SQLite index, so an interrupted run resumes where it stopped. Results are appended to `Ket_qua_AndroZoo.xlsx`.

```
python tai_androzoo.py --so-luong 5000 --luong 4
```

Main options: `--so-luong` number of APKs to download, `--luong` parallel download threads, `--nhom` sample group (no engine flag, flagged), `--tu-nam` / `--den-nam` year range, `--vt-toi-thieu` / `--vt-toi-da` range of AndroZoo's VirusTotal count, `--dich` destination folder, `--tiep-tuc` resume, `--du-tru` free disk space to keep (GB).

`doi_soat_androzoo.py` reconciles the three places that can drift apart (APK folder, result sheet, SQLite index) and writes the list of hashes that need to be downloaded again.

### GitHub

`github_sources.csv` lists the 16 repositories of malware samples used in the paper. Samples in these repositories are often nested archives without an `.apk` extension, so both scripts recognise an APK by its content: a valid ZIP file that contains `AndroidManifest.xml` and at least one `classes*.dex`. Samples whose internal timestamp is older than `--nam-toi-thieu` are skipped, and samples already present (same SHA-256) are not copied twice.

```
python thu_gom_github_apk.py --danh-sach github_sources.csv --dich <output_folder> --nam-toi-thieu 2020
python thu_gom_tu_zip.py --thu-muc-nguon <folder_with_zip_files> --dich <output_folder> --nam-toi-thieu 2020
```

## Step 2. Labelling

### Stage 1: VirusTotal lookup

`quet_virustotal.py` looks up every APK in a folder through the VirusTotal API v3 by its SHA-256 hash (`GET /api/v3/files/{sha256}`). Files are never uploaded. For each sample it stores the full JSON report in `phan_hoi_json/` and writes one row to `Ket_qua_VirusTotal.xlsx` with the number of engines that flagged the file, the total number of engines, the first submission date, the family and threat category suggested by VirusTotal, and a keyword-based category hint used later for cross-checking. Several keys can be used in rotation; the script queries each key's real quota and slows down automatically when it receives HTTP 429.

```
python quet_virustotal.py --thu-muc <apk_folder> --nguong 1
```

Main options: `--thu-muc` APK folder, `--ket-qua` output folder, `--nguong` minimum number of engines for the malware label (default 1), `--nhip` seconds between two calls of the same key, `--gioi-han-ngay` daily limit per key, `--noi-tiep` continue a previous run, `--kiem-tra-key` check the keys and exit.

### Stage 2: final label with Gemini

`gan_nhan_gemini.py` reads the reports in `phan_hoi_json/`. A sample flagged by no engine is labelled Benign directly. Every other sample is malware and is sent to Gemini, in batches of about 70 samples, to be placed in one of four categories. For each sample the prompt contains the number of flagging engines, the family and threat category aggregated by VirusTotal, behaviour tags and up to 25 engine results. When a sample shows signs of several categories, the priority order is Banking malware, SMS malware, Adware, Riskware; a sample without clear evidence for the first three is labelled Riskware. The model must return a label, a self-reported confidence between 0 and 1 and a short reason; the output is constrained by a JSON schema that only allows the four category names, and the temperature is 0. The full prompt is built in the function `dung_prompt`, and the category descriptions are in `MO_TA_NHAN`.

Raw Gemini answers are stored per sample in `phan_hoi_gemini/`, and the final labels in `Ket_qua_GanNhan.xlsx` (column `Nhan_bai_bao`, with `Khop_goi_y` comparing the Gemini label with the keyword hint).

```
python gan_nhan_gemini.py --thu-muc-json phan_hoi_json --model gemini-3.6-flash --lo 70
```

Main options: `--model` Gemini model name, `--lo` samples per call, `--so-engine` engine results per sample in the prompt (default 25), `--uu-tien` category priority order, `--thu` print the first prompt without calling the API, `--tinh-lai` rebuild the Excel file from saved answers.

## Step 3. Static features

`trich_xuat_tinh.py` uses androguard to extract static features from the ZIP structure, `AndroidManifest.xml` and the DEX bytecode, in three stages:

1. **Raw record extraction.** Each APK is analysed in a worker process and its full raw record is compressed and stored in `dac_trung.sqlite`, keyed by file name (the SHA-256). APKs already in the database are skipped, and a crashed worker pool is rebuilt automatically.
2. **Normalisation.** Class names are reduced to their three-level package prefix (for example `Lcom/qihoo/util/AppCls;` becomes `Lcom/qihoo/util/`), which keeps library and packer traces without app-specific names. Strings are kept as domains only if they end with a valid top-level domain, and are reduced to the registered domain; Java identifiers with dots are discarded.
3. **Vocabulary selection and vectorisation.** Two passes over the database: the first counts in how many samples each feature appears, drops features seen in a single sample and keeps the 20,000 most frequent; the second writes one row per sample with 32 fixed numeric attributes and the 20,000 vocabulary columns.

Because the raw records are kept, the vocabulary can be rebuilt with other criteria (`--min-df`, `--max-features`, ...) without analysing the APKs again.

```
python trich_xuat_tinh.py --link LinkAPK.txt --output <output_folder> --workers 3
```

`LinkAPK.txt` lists the APK folders, one per line, in the form `path | SourceName`; the source name is written in the `source` column.

| Option | Meaning |
|---|---|
| `--workers` | number of extraction processes |
| `--chi-trich-xuat` | only extract raw records |
| `--chi-xuat-csv` | only build the vocabulary and the CSV from the database |
| `--lam-lai-loi` | retry samples that failed before |
| `--min-df`, `--max-df-ratio`, `--max-features` | vocabulary selection |
| `--cap-goi` | depth of the class package prefix (default 3) |

Outputs:

| File | Content |
|---|---|
| `dac_trung.sqlite` | raw feature record of every APK |
| `apk_ml_dataset.csv` | feature matrix: `file_name`, `source`, `sha256`, 32 numeric attributes, 20,000 vocabulary columns named `<group>::<value>` |
| `feature_vocabulary.csv` | vocabulary with the number and share of samples containing each feature |

## Step 4. Dynamic features

The tool in `4_dynamic_features/` uses only the standard Android Emulator and ADB, without root, so several emulators can run in parallel (one worker per emulator). For each APK it clears logcat, installs the app and grants its declared permissions, launches the main activity, and runs Monkey (150 random UI events, 100 ms apart). While Monkey runs, it samples the app every 2 seconds for 20 seconds: CPU, memory (PSS, RSS, Java heap, native heap), processes and threads, sockets and bytes sent and received by the app's UID. It then collects logcat, stops and uninstalls the app. The samples are summarised into 30 features in seven groups (execution status, CPU, memory, processes, network, system log, component events).

```
python main.py --apk-dir <apk_folder> --output <output_folder> --runtime 20 --workers 4 --resume
```

Options: `--apk-dir` APK folder, `--output` output folder, `--workers` number of emulators, `--serials` explicit emulator serials, `--runtime` observation time in seconds, `--resume` skip APKs already processed, `--test-apk` run a single APK. Other settings are in `config.yaml`.

Outputs: `dynamic_features.csv` (SHA-256, run information and the 30 features), `processed.jsonl` and `failed.jsonl` (checkpoints) and `raw/` (per-sample sampling data and logcat).

Use emulators without real accounts or personal data, without shared folders, on an isolated NAT network.

## Export to other formats

`apk_ml_dataset.csv` can be used as it is with pandas or scikit-learn. `5_export_formats/chuyen_dinh_dang.py` converts it, together with a label file, into formats read directly by other tools:

| Format | Files | Tools |
|---|---|---|
| `arff` | `AndroidMalSet2026.arff` (sparse ARFF, class attribute last) | Weka (Explorer, Experimenter, command line) |
| `libsvm` | `AndroidMalSet2026.libsvm` (1-based indices, class index as label) | scikit-learn `load_svmlight_file`, XGBoost, LightGBM, LIBSVM, Weka `LibSVMLoader` |
| `npz` | `X.npz` (SciPy CSR, float32), `y.npy`, `classes.txt` | scikit-learn, Keras/TensorFlow, PyTorch in Anaconda, Jupyter Notebook or Google Colab |

Every run also writes `feature_names.txt` (column order) and `sample_ids.csv` (`file_name`, `source`, `sha256`, `label` in row order).

```
python chuyen_dinh_dang.py --csv apk_ml_dataset.csv --output export --nhan labels.xlsx --cot-nhan Nhan_bai_bao --dinh-dang arff libsvm npz
```

| Option | Meaning |
|---|---|
| `--csv` | feature matrix written by `trich_xuat_tinh.py` |
| `--output` | output folder |
| `--dinh-dang` | one or more of `arff`, `libsvm`, `npz` |
| `--nhan` | label file (CSV or XLSX) joined on SHA-256 |
| `--cot-sha`, `--cot-nhan` | SHA-256 and label column names in the label file |
| `--nhi-phan` | binary task: every label other than Benign becomes Malware |
| `--chi-ma-doc` | keep malware samples only (four-category task) |
| `--giu-khong-nhan` | keep samples without a label (dropped by default) |
| `--khoi` | rows read per chunk (default 2,000) |
| `--gioi-han` | read only the first N rows, for a quick test |

The CSV is read in chunks, so ARFF and LibSVM files are written without loading the whole matrix into memory; the NPZ export keeps the sparse matrix in memory. `vi_du_su_dung.ipynb` shows how to load the NPZ files and train a Random Forest (scikit-learn) and a small neural network (Keras) on mini-batches. With 20,032 attributes, give Weka more memory, for example `java -Xmx8g -jar weka.jar`.

## Linking the files

All outputs share the SHA-256 key: join the static feature matrix, the dynamic features and the labels on `sha256`. A different labelling threshold can be applied afterwards from the number of flagging engines stored for each sample: Benign when no engine flags the sample, malware when at least K engines do, and excluded in between.

## Data availability

The dataset files are not stored in this repository because of their size (about 4.9 GB for the feature matrix and 84 GB for the raw records) and because malware samples are not redistributed. They are available from the authors on reasonable request. Samples can be downloaded again from AndroZoo by SHA-256.
