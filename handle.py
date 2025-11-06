# -*- coding: utf-8 -*-

import json
import shutil
import os
import re
import threading
import time

# 디렉토리 경로 설정 (절대 경로 사용)
final_report_dir = '/home/goat/FinalReport'
processed_dir = '/home/goat/Maildir/processed'
clean_dir = '/home/goat/Maildir/clean'
problem_dir = '/home/goat/Maildir/problem'
isolation_dir = '/home/goat/Maildir/isolation'

# 분류용 유틸: HWP/HWPX classification 읽기
def get_hwp_classification(report_dict):
    """
    HWP/HWPX Analysis 배열에서 classification을 추출해 최종 등급을 반환.
    - 여러 항목이 있으면 malicious > suspicious > benign 우선순위 적용
    - type 이 HWP/HWPX 인 것만 고려
    - 못 찾으면 None 반환
    """
    key = None
    if "HWP/HWPX Analysis" in report_dict and isinstance(report_dict["HWP/HWPX Analysis"], list):
        key = "HWP/HWPX Analysis"
    else:
        # 혹시 키가 변형돼 있을 가능성 대비(안 쓰면 제거 가능)
        for k in report_dict.keys():
            if "HWP" in k and "Analysis" in k and isinstance(report_dict[k], list):
                key = k
                break

    if not key:
        return None

    # 수집
    has_mal = False
    has_susp = False
    has_benign = False

    for item in report_dict[key]:
        try:
            ftype = str(item.get("type", "")).upper()
            if ftype not in ("HWP", "HWPX"):
                continue
            cls = str(item.get("classification", "")).lower()
            if cls == "malicious":
                has_mal = True
            elif cls == "suspicious":
                has_susp = True
            elif cls == "benign":
                has_benign = True
        except Exception:
            continue

    if has_mal:
        return "malicious"
    if has_susp:
        return "suspicious"
    if has_benign:
        return "benign"
    return None

def ensure_dirs():
    for d in (clean_dir, problem_dir, isolation_dir):
        os.makedirs(d, exist_ok=True)

def process_files():
    print("스크립트가 시작되었습니다.")

    # 사전 생성
    ensure_dirs()

    # FinalReport 디렉토리의 파일 목록 출력
    final_report_files = os.listdir(final_report_dir)
    print("FinalReport 디렉토리의 파일 목록:", final_report_files)

    # processed 디렉토리의 파일 목록 출력
    all_files = os.listdir(processed_dir)
    print("processed 디렉토리의 파일 목록:", all_files)

    # 정규식에 맞는 파일 필터링
    processed_files = [f for f in all_files if re.match(r'^\d+\.Vfd01I[a-zA-Z0-9]+M\d+\.mail\.redhat12\.xyz$', f)]

    if not processed_files:
        print("processed 디렉토리에 정규식에 맞는 파일이 없습니다.")
    else:
        print("처리할 파일 목록:", processed_files)

    # 파일들을 처리
    for processed_file in processed_files:
        # 파일 번호 추출
        match = re.match(r'^(\d+)\.Vfd01I[a-zA-Z0-9]+M\d+\.mail\.redhat12\.xyz$', processed_file)
        if not match:
            print(f"파일 번호 추출 실패: {processed_file}")
            continue
        file_number = match.group(1)

        print(f"처리 중인 파일 번호: {file_number}")

        # 해당하는 FinalReport JSON 파일 찾기
        final_report_file = None
        for fr_file in final_report_files:
            if fr_file.startswith(file_number) and fr_file.endswith('_FinalReport.json'):
                final_report_file = os.path.join(final_report_dir, fr_file)
                break

        # JSON 파일이 존재하는지 확인
        if not final_report_file or not os.path.exists(final_report_file):
            print(f"JSON 파일이 존재하지 않습니다: {final_report_file}")
            continue

        # JSON 파일 읽기 및 파싱
        try:
            with open(final_report_file, 'r', encoding='utf-8') as f:
                # BOM 방어
                raw = f.read()
                if raw.startswith('\ufeff'):
                    raw = raw.lstrip('\ufeff')
                data = json.loads(raw)
        except Exception as e:
            print(f"JSON 파싱 오류: {final_report_file}, err={e}")
            continue

        # 1) HWP/HWPX classification 우선
        classification = get_hwp_classification(data)

        # 2) 폴백: 그래도 못 찾으면 기존 Cuckoo 점수 기준 (원하면 제거 가능)
        score = None
        if classification is None:
            for entry in data.get("Cuckoo", []):
                m = re.search(r"The score of this file is (\d+\.\d+) out of 10", entry)
                if m:
                    try:
                        score = float(m.group(1))
                    except Exception:
                        pass
                    break

        # 이동할 대상 디렉토리 결정
        target_dir = None
        reason = ""

        if classification == "malicious":
            target_dir = problem_dir
            reason = "HWP classification = malicious"
        elif classification == "suspicious":
            target_dir = isolation_dir
            reason = "HWP classification = suspicious"
        elif classification == "benign":
            target_dir = clean_dir
            reason = "HWP classification = benign"
        else:
            # 폴백: Cuckoo 점수
            if score is not None:
                if 0 <= score <= 4:
                    target_dir = clean_dir
                    reason = f"Cuckoo score fallback: {score}"
                elif 5 <= score < 6:
                    target_dir = isolation_dir
                    reason = f"Cuckoo score fallback: {score}"
                elif 6 <= score <= 10:
                    target_dir = problem_dir
                    reason = f"Cuckoo score fallback: {score}"

        processed_file_path = os.path.join(processed_dir, processed_file)

        if target_dir:
            try:
                shutil.move(processed_file_path, target_dir)
                print(f"[이동 완료] {processed_file} -> {target_dir} ({reason})")
            except Exception as e:
                print(f"[이동 실패] {processed_file} -> {target_dir}, err={e}")
        else:
            print(f"이동 대상 미결정: {processed_file} (HWP classification/점수 없음)")

    print("스크립트가 종료되었습니다.")

def monitor_dirs():
    processed_files_set = set()
    while True:
        try:
            all_files = os.listdir(processed_dir)
        except FileNotFoundError:
            all_files = []

        for processed_file in all_files:
            if processed_file in processed_files_set:
                continue

            processed_files_set.add(processed_file)
            process_files()

        time.sleep(10)  # 10초마다 디렉토리 확인

if __name__ == "__main__":
    monitor_thread = threading.Thread(target=monitor_dirs)
    monitor_thread.start()

    print("Monitoring directories...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping directory monitoring...")
        monitor_thread.join()

