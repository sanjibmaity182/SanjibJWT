<?php
// PHPUnit test for SanjibJWT
use PHPUnit\Framework\TestCase;

class SanjibJWTTest extends TestCase {
    public function testGenerateAndValidateToken() {
        require_once __DIR__ . '/../src/SanjibJWT.php';
        $jwt = new SanjibJWT([
            'secret' => 'test-secret',
            'allowed_ips' => ['127.0.0.1']
        ]);
        
        // Generate a new token
        $tokenArr = $jwt->createToken([
            'user_id' => 42,
            'username' => 'testuser',
            'role' => 'tester'
        ], [
            'app' => 'TestSuite',
            'env' => 'testing'
        ]);
        
        $this->assertIsArray($tokenArr);
        $this->assertArrayHasKey('access_token', $tokenArr);
        $this->assertArrayHasKey('expires_in', $tokenArr);
        $this->assertArrayHasKey('token_type', $tokenArr);
        $this->assertEquals('Bearer', $tokenArr['token_type']);
        
        // Validate the token
        $payload = $jwt->validateToken($tokenArr['access_token'], true, [
            'app' => 'TestSuite',
            'env' => 'testing'
        ]);
        $this->assertIsArray($payload);
        $this->assertEquals(42, $payload['user_id']);
        $this->assertEquals('testuser', $payload['username']);
        $this->assertEquals('tester', $payload['role']);
        $this->assertArrayHasKey('iat', $payload);
        $this->assertArrayHasKey('exp', $payload);
        $this->assertArrayHasKey('jti', $payload);
    }
}
