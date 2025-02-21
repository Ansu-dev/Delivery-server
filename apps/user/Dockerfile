# 어떤 이미지를 사용할지
FROM node:alpine AS development

WORKDIR /usr/src/app

# package.json 복사해오기(docker내 현재위치로)
COPY package*.json ./

# Dependency 설치하기
RUN npm i

# 현재 모든 파일을 WORKDIR로 옮김
COPY . .

# 커맨드 실행
CMD ["npm", "run", "start:dev", "user"]

