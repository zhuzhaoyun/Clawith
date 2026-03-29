import { useState, useEffect } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { authApi } from '../services/api';

export default function VerifyEmail() {
    const { t, i18n } = useTranslation();
    const [searchParams] = useSearchParams();
    const token = searchParams.get('token');
    const [status, setStatus] = useState<'verifying' | 'success' | 'error'>('verifying');
    const [message, setMessage] = useState('');

    const isChinese = i18n.language?.startsWith('zh');

    useEffect(() => {
        if (!token) {
            setStatus('error');
            setMessage(isChinese ? '验证链接无效或已过期' : 'Invalid or expired verification link');
            return;
        }

        authApi.verifyEmail(token)
            .then(() => {
                setStatus('success');
                setMessage(isChinese ? '邮箱验证成功！' : 'Email verified successfully!');
            })
            .catch((err: any) => {
                setStatus('error');
                setMessage(err.message || (isChinese ? '验证失败，链接可能已过期' : 'Verification failed, link may have expired'));
            });
    }, [token, isChinese]);

    return (
        <div style={{
            minHeight: '100vh',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            background: 'var(--bg-primary)',
            padding: '20px',
        }}>
            <div style={{
                maxWidth: '400px',
                width: '100%',
                textAlign: 'center',
                padding: '40px',
                borderRadius: '16px',
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border-subtle)',
            }}>
                {status === 'verifying' && (
                    <>
                        <div style={{ fontSize: '48px', marginBottom: '20px' }}>⏳</div>
                        <h2 style={{ marginBottom: '12px' }}>{isChinese ? '正在验证...' : 'Verifying...'}</h2>
                        <p style={{ color: 'var(--text-secondary)' }}>{isChinese ? '请稍候' : 'Please wait'}</p>
                    </>
                )}

                {status === 'success' && (
                    <>
                        <div style={{ fontSize: '48px', marginBottom: '20px', color: '#16a34a' }}>✓</div>
                        <h2 style={{ marginBottom: '12px', color: '#16a34a' }}>{message}</h2>
                        <p style={{ color: 'var(--text-secondary)', marginBottom: '24px' }}>
                            {isChinese ? '您的邮箱已成功验证，现在可以登录使用所有功能。' : 'Your email has been verified. You can now log in and use all features.'}
                        </p>
                        <Link to="/login" style={{
                            display: 'inline-block',
                            padding: '10px 24px',
                            background: 'var(--accent-primary)',
                            color: '#fff',
                            borderRadius: '8px',
                            textDecoration: 'none',
                            fontSize: '14px',
                        }}>
                            {isChinese ? '去登录' : 'Go to Login'}
                        </Link>
                    </>
                )}

                {status === 'error' && (
                    <>
                        <div style={{ fontSize: '48px', marginBottom: '20px', color: '#ef4444' }}>✕</div>
                        <h2 style={{ marginBottom: '12px', color: '#ef4444' }}>{isChinese ? '验证失败' : 'Verification Failed'}</h2>
                        <p style={{ color: 'var(--text-secondary)', marginBottom: '24px' }}>{message}</p>
                        <div style={{ display: 'flex', gap: '12px', justifyContent: 'center' }}>
                            <Link to="/login" style={{
                                display: 'inline-block',
                                padding: '10px 24px',
                                background: 'var(--bg-tertiary)',
                                color: 'var(--text-primary)',
                                borderRadius: '8px',
                                textDecoration: 'none',
                                fontSize: '14px',
                            }}>
                                {isChinese ? '返回登录' : 'Back to Login'}
                            </Link>
                        </div>
                    </>
                )}
            </div>
        </div>
    );
}
