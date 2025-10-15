# internal_security_scan
이 스크립트는 Windows 기반 서버의 내부 보안 점검 자동화를 목적으로 작성되었습니다.   Nmap, Trivy, YARA, Osquery 등을 통합 실행하여 다음 항목을 자동으로 검사하고 리포트화합니다.

### ⚙️ 실행 명령
PS C:\sec> .\internal_security_scan.ps1 -RunYara

<img width="1696" height="667" alt="깃허브에 정리01" src="https://github.com/user-attachments/assets/a347f5b2-147c-40e3-ab71-45d15d795989" />

실행 시 C:\sec_reports\<날짜> 폴더에 자동 리포트가 생성됩니다.
C:\sec_reports\2025-10-15\
├─ nmap_2025-10-15\
├─ trivy_fs_2025-10-15.json
├─ yara_2025-10-15\
├─ osquery_2025-10-15\
└─ critical_summary_2025-10-15.txt

<img width="1686" height="663" alt="깃허브에 정리03" src="https://github.com/user-attachments/assets/16736074-2bcf-46c8-aa66-0abb3013af5c" />


🧩 활용 예시

- 내부 점검 주기 자동화 (주간/월간 스케줄러 등록)

- ISO27001 / ISMS-P 내부 감사 증적 자동 수집

- 실시간 취약점 대응 (Trivy DB + NVD 연동)

- 인시던트 발생 시 신속한 로컬 감사 기반 확보

<img width="1692" height="670" alt="깃허브에 정리02" src="https://github.com/user-attachments/assets/798ecac8-1dfb-4252-b4e3-e83b93d759f0" />


#※참고

본 프로젝트는 PowerShell 7.x 환경에서 실행되며,
외부 툴은 PATH 또는 스크립트 내 절대경로로 지정되어 있어야 합니다.
- nmap.exe
- yara64.exe
- trivy.exe
- osqueryi.exe
