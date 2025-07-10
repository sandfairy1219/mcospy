const { MongoClient } = require('mongodb');
require('dotenv').config();

class LicenseVerifier {
  constructor() {
    this.client = null;
    this.db = null;
  }

  async connect() {
    try {
      console.log(process.env.MONGODB_URI);
      this.client = new MongoClient(process.env.MONGODB_URI);
      await this.client.connect();
      this.db = this.client.db("sanabi");
      console.log('MongoDB 연결 성공');
      return true;
    } catch (error) {
      console.error('MongoDB 연결 실패:', error.message);
      return false;
    }
  }

  async verifyLicense(tokenCode) {
    if (!this.db) {
      throw new Error('데이터베이스가 연결되지 않았습니다');
    }

    try {
      const tokensCollection = this.db.collection('tokens');
      const token = await tokensCollection.findOne({ code: tokenCode });

      if (!token) {
        return {
          valid: false,
          message: '유효하지 않은 라이선스 코드입니다'
        };
      }

      const currentTime = Date.now();
      const expirationTime = new Date(token.expiration).getTime();

      if (currentTime > expirationTime) {
        return {
          valid: false,
          message: '라이선스가 만료되었습니다'
        };
      }

      return {
        valid: true,
        message: '라이선스 검증 성공',
        expiresAt: token.expiration
      };
    } catch (error) {
      console.error('라이선스 검증 오류:', error.message);
      return {
        valid: false,
        message: '라이선스 검증 중 오류가 발생했습니다'
      };
    }
  }

  async disconnect() {
    if (this.client) {
      await this.client.close();
      console.log('MongoDB 연결 종료');
    }
  }
}

module.exports = LicenseVerifier;