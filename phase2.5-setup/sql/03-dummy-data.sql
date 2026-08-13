-- 더미 고객 데이터 (200건)
-- 유출 시나리오에서 공격자가 탈취를 시도하는 대상

INSERT INTO wp_customers (name, email, phone, company, project_type, contract_amount, status) VALUES
('김민수', 'minsu.kim@koreantech.co.kr', '010-1234-5678', '코리안테크', '클라우드 마이그레이션', 45000000, 'active'),
('이서연', 'seoyeon@dataflow.kr', '010-2345-6789', '데이터플로우', '보안 컨설팅', 32000000, 'active'),
('박준혁', 'junhyuk.park@smartbiz.com', '010-3456-7890', '스마트비즈', 'ERP 구축', 78000000, 'active'),
('최유진', 'yujin@nexgen.co.kr', '010-4567-8901', '넥스젠솔루션', '웹 개발', 25000000, 'completed'),
('정하늘', 'haneul.j@cloudway.kr', '010-5678-9012', '클라우드웨이', '인프라 구축', 56000000, 'active'),
('강도윤', 'doyun.kang@ailab.kr', '010-6789-0123', 'AI연구소', 'AI 시스템 구축', 120000000, 'active'),
('윤서진', 'seojin@greendata.com', '010-7890-1234', '그린데이터', '데이터센터 이전', 95000000, 'pending'),
('임채원', 'chaewon@fintech.kr', '010-8901-2345', '핀테크코리아', '보안 인증', 42000000, 'active'),
('한지민', 'jimin.han@edusoft.co.kr', '010-9012-3456', '에듀소프트', 'LMS 개발', 38000000, 'completed'),
('송태양', 'taeyang@solarit.kr', '010-0123-4567', '솔라IT', '모니터링 시스템', 28000000, 'active'),
('오수빈', 'subin.oh@medisys.kr', '010-1111-2222', '메디시스', '의료 IT 구축', 67000000, 'active'),
('배현우', 'hyunwoo@logistech.com', '010-2222-3333', '로지스테크', '물류 시스템', 53000000, 'pending'),
('신예린', 'yerin@designpro.kr', '010-3333-4444', '디자인프로', '웹 리뉴얼', 18000000, 'completed'),
('류건호', 'gunho@securewall.kr', '010-4444-5555', '시큐어월', '방화벽 구축', 72000000, 'active'),
('문서현', 'seohyun.m@retailplus.kr', '010-5555-6666', '리테일플러스', 'POS 시스템', 41000000, 'active'),
('장우성', 'woosung@biganalytics.kr', '010-6666-7777', '빅애널리틱스', '빅데이터 분석', 88000000, 'active'),
('권나연', 'nayeon@hrstartup.com', '010-7777-8888', 'HR스타트업', '인사 시스템', 33000000, 'pending'),
('조성민', 'sungmin@gamedev.kr', '010-8888-9999', '게임개발사', '서버 구축', 46000000, 'completed'),
('황다은', 'daeun@travelit.kr', '010-9999-0000', '트래블IT', '예약 시스템', 37000000, 'active'),
('노지훈', 'jihoon@automate.kr', '010-1010-2020', '오토메이트', 'RPA 구축', 59000000, 'active');

-- 추가 180건 (회사명·프로젝트 변형)
INSERT INTO wp_customers (name, email, phone, company, project_type, contract_amount, status)
SELECT
    CONCAT(
        ELT(FLOOR(1 + RAND() * 10), '김','이','박','최','정','강','윤','임','한','송'),
        ELT(FLOOR(1 + RAND() * 10), '민수','서연','준혁','유진','하늘','도윤','서진','채원','지민','태양')
    ),
    CONCAT('user', seq, '@company', FLOOR(RAND()*100), '.kr'),
    CONCAT('010-', LPAD(FLOOR(RAND()*10000),4,'0'), '-', LPAD(FLOOR(RAND()*10000),4,'0')),
    CONCAT(
        ELT(FLOOR(1 + RAND() * 8), '테크','데이터','클라우드','시큐어','스마트','디지털','넥스트','퓨처'),
        ELT(FLOOR(1 + RAND() * 6), '솔루션','시스템','랩','웨이','프로','코리아')
    ),
    ELT(FLOOR(1 + RAND() * 8), '웹 개발','보안 컨설팅','클라우드 구축','ERP 구축','모바일 앱','인프라 운영','데이터 분석','시스템 통합'),
    FLOOR(15000000 + RAND() * 100000000),
    ELT(FLOOR(1 + RAND() * 3), 'active','completed','pending')
FROM (
    SELECT @row := @row + 1 AS seq
    FROM information_schema.columns a,
         information_schema.columns b,
         (SELECT @row := 20) r
    LIMIT 180
) numbers;


-- 문의 내역 더미 데이터 (50건)
INSERT INTO wp_inquiries (name, email, message, ip_address, created_at) VALUES
('김태호', 'taeho@naver.com', '클라우드 마이그레이션 견적 문의드립니다.', '211.234.56.78', '2024-07-01 09:15:00'),
('이수진', 'sujin@gmail.com', '보안 취약점 진단 서비스에 대해 알고 싶습니다.', '175.123.45.67', '2024-07-02 14:30:00'),
('박영호', 'youngho@daum.net', '기존 시스템 유지보수 계약 관련 문의', '220.78.90.12', '2024-07-03 11:00:00'),
('최은비', 'eunbi@company.co.kr', '인프라 구축 프로젝트 일정 조율 가능한가요?', '119.56.78.90', '2024-07-05 16:45:00'),
('정민재', 'minjae@naver.com', 'ERP 도입 컨설팅 비용이 궁금합니다.', '203.45.67.89', '2024-07-08 10:20:00'),
('강서윤', 'seoyun@gmail.com', '웹사이트 리뉴얼 포트폴리오 확인 가능한가요?', '112.34.56.78', '2024-07-10 13:15:00'),
('윤재현', 'jaehyun@kakao.com', '데이터센터 이전 작업 견적 요청합니다.', '58.123.45.67', '2024-07-12 09:30:00'),
('임하린', 'harin@naver.com', '모바일 앱 개발 외주 가능한지 문의드립니다.', '211.45.67.89', '2024-07-15 15:00:00'),
('한승우', 'seungwoo@gmail.com', '네트워크 보안 솔루션 도입 상담 요청', '175.67.89.01', '2024-07-18 11:45:00'),
('송지아', 'jia@company.kr', 'AI 챗봇 구축 프로젝트 제안서 요청합니다.', '220.12.34.56', '2024-07-20 14:00:00'),
('오현준', 'hyunjun@daum.net', 'IT 아웃소싱 서비스 범위 문의', '119.23.45.67', '2024-07-22 10:30:00'),
('배수아', 'sua@naver.com', '정보보호관리체계(ISMS) 인증 컨설팅 가능한가요?', '203.56.78.90', '2024-07-25 16:15:00'),
('신동현', 'donghyun@gmail.com', '서버 호스팅에서 클라우드로 전환 비용 문의', '112.67.89.01', '2024-07-28 09:00:00'),
('류하은', 'haeun@kakao.com', '사내 그룹웨어 커스터마이징 가능한가요?', '58.78.90.12', '2024-08-01 13:30:00'),
('문준서', 'junseo@naver.com', '보안관제 서비스(SOC) 월정액 상품 있나요?', '211.89.01.23', '2024-08-03 11:15:00');

-- 추가 35건
INSERT INTO wp_inquiries (name, email, message, ip_address, created_at)
SELECT
    CONCAT(
        ELT(FLOOR(1 + RAND() * 10), '김','이','박','최','정','강','윤','임','한','송'),
        ELT(FLOOR(1 + RAND() * 8), '태호','수진','영호','은비','민재','서윤','재현','하린')
    ),
    CONCAT('inquiry', seq, '@', ELT(FLOOR(1+RAND()*4),'naver.com','gmail.com','daum.net','kakao.com')),
    ELT(FLOOR(1 + RAND() * 5),
        '서비스 견적 문의드립니다.',
        '프로젝트 일정 상담 요청합니다.',
        '기술 지원 가능 여부 확인 부탁드립니다.',
        '포트폴리오 자료 요청합니다.',
        '파트너십 제안 관련 연락드립니다.'
    ),
    CONCAT(
        FLOOR(100 + RAND() * 155), '.',
        FLOOR(1 + RAND() * 254), '.',
        FLOOR(1 + RAND() * 254), '.',
        FLOOR(1 + RAND() * 254)
    ),
    DATE_ADD('2024-07-01', INTERVAL FLOOR(RAND() * 45) DAY)
FROM (
    SELECT @row2 := @row2 + 1 AS seq
    FROM information_schema.columns a,
         (SELECT @row2 := 15) r
    LIMIT 35
) numbers;
