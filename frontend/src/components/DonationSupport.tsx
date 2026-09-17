import { useEffect, useId, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { QRCodeSVG } from 'qrcode.react';
import { IconCheck, IconChevronLeft, IconCopy, IconHeart } from './ui/Icons';

const DONATION_WALLETS = {
  btc: {
    id: 'btc',
    name: 'Bitcoin (BTC)',
    network: 'Rede Bitcoin Mainnet',
    address: 'bc1qdmfeatvcd6w43d6ld7jda8ypw2dez224yul6fr',
    symbol: '₿',
    accent: 'hover:border-amber-500/40 hover:text-amber-400',
  },
  eth: {
    id: 'eth',
    name: 'Ethereum (ETH)',
    network: 'Rede Ethereum (ERC-20)',
    address: '0xFc99D8DEF31dB48EF05a01233e85547E47D18F9C',
    symbol: 'Ξ',
    accent: 'hover:border-indigo-500/40 hover:text-indigo-400',
  },
  usdt: {
    id: 'usdt',
    name: 'Tether (USDT)',
    network: 'Rede TRON (TRC-20)',
    address: 'TXMJdx8vGmAYhDUUwH1zKDoZP3j3DG5PDW',
    symbol: '₮',
    accent: 'hover:border-emerald-500/40 hover:text-emerald-400',
    warning:
      'Apenas rede TRON (TRC-20). Outras redes causarão perda permanente.',
  },
} as const;

type WalletId = keyof typeof DONATION_WALLETS;

const WALLET_ORDER: readonly WalletId[] = ['btc', 'eth', 'usdt'];

const COIN_TOOLTIPS: Record<WalletId, string> = {
  btc: 'Bitcoin (BTC)',
  eth: 'Ethereum (ETH)',
  usdt: 'USDT (TRC-20)',
};

const DESKTOP_MQ = '(min-width: 640px)';

export function DonationSupport() {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [selected, setSelected] = useState<WalletId | null>(null);
  const [copied, setCopied] = useState(false);
  const [qrSize, setQrSize] = useState(128);
  const rootRef = useRef<HTMLDivElement | null>(null);
  const panelId = useId();
  const copyTimerRef = useRef<number | null>(null);

  function closeAndReset(): void {
    setOpen(false);
    setSelected(null);
    setCopied(false);
    if (copyTimerRef.current !== null) {
      window.clearTimeout(copyTimerRef.current);
      copyTimerRef.current = null;
    }
  }

  useEffect(() => {
    const mq = window.matchMedia(DESKTOP_MQ);
    const syncQr = (): void => {
      setQrSize(mq.matches ? 140 : 128);
    };
    syncQr();
    mq.addEventListener('change', syncQr);
    return () => mq.removeEventListener('change', syncQr);
  }, []);

  useEffect(() => {
    if (!open) {
      return;
    }

    function onPointerDown(event: MouseEvent | TouchEvent): void {
      const root = rootRef.current;
      if (!root) {
        return;
      }
      const target = event.target;
      if (target instanceof Node && !root.contains(target)) {
        closeAndReset();
      }
    }

    function onKeyDown(event: KeyboardEvent): void {
      if (event.key === 'Escape') {
        closeAndReset();
      }
    }

    document.addEventListener('mousedown', onPointerDown);
    document.addEventListener('touchstart', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('mousedown', onPointerDown);
      document.removeEventListener('touchstart', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [open]);

  useEffect(() => {
    return () => {
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
    };
  }, []);

  async function handleCopy(address: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(address);
      setCopied(true);
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
      copyTimerRef.current = window.setTimeout(() => {
        setCopied(false);
        copyTimerRef.current = null;
      }, 2000);
    } catch {
      setCopied(false);
    }
  }

  const activeWallet = selected ? DONATION_WALLETS[selected] : null;

  return (
    <div className="donation-support" ref={rootRef}>
      <button
        type="button"
        className={`icon-btn donation-trigger${open ? ' active' : ''}`}
        title={t('donation.support')}
        aria-label={t('donation.support')}
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => {
          if (open) {
            closeAndReset();
          } else {
            setOpen(true);
            setSelected(null);
            setCopied(false);
          }
        }}
      >
        <IconHeart size="nav" />
      </button>

      {open && (
        <>
          <div
            className="donation-backdrop"
            role="presentation"
            aria-hidden="true"
            onClick={closeAndReset}
          />
          <div
            id={panelId}
            className="donation-popover"
            role="dialog"
            aria-modal="true"
            aria-label={t('donation.support')}
          >
            {activeWallet === null ? (
              <div className="donation-step donation-step-select">
                <p className="donation-step-label">{t('donation.choose')}</p>
                <div className="donation-coin-row" role="list">
                  {WALLET_ORDER.map((id) => {
                    const wallet = DONATION_WALLETS[id];
                    return (
                      <button
                        key={id}
                        type="button"
                        role="listitem"
                        className={`donation-coin donation-coin--${id}`}
                        title={COIN_TOOLTIPS[id]}
                        aria-label={COIN_TOOLTIPS[id]}
                        data-accent={wallet.accent}
                        onClick={() => {
                          setSelected(id);
                          setCopied(false);
                        }}
                      >
                        <span aria-hidden="true">{wallet.symbol}</span>
                      </button>
                    );
                  })}
                </div>
              </div>
            ) : (
              <div className="donation-step donation-step-detail">
                <header className="donation-detail-head">
                  <button
                    type="button"
                    className="icon-btn donation-back"
                    aria-label={t('donation.back')}
                    onClick={() => {
                      setSelected(null);
                      setCopied(false);
                    }}
                  >
                    <IconChevronLeft size="sm" />
                  </button>
                  <div className="donation-detail-titles">
                    <span className="donation-coin-name">
                      {activeWallet.name}
                    </span>
                    <span className="donation-network-badge">
                      {activeWallet.network}
                    </span>
                  </div>
                </header>

                <div className="donation-qr-wrap">
                  <QRCodeSVG
                    value={activeWallet.address}
                    size={qrSize}
                    bgColor="#0d1b1e"
                    fgColor="#2dd4bf"
                    level="M"
                    marginSize={2}
                    title={activeWallet.name}
                  />
                </div>

                <div className="donation-address-row">
                  <code className="donation-address">
                    {activeWallet.address}
                  </code>
                  <button
                    type="button"
                    className="donation-copy-btn"
                    title={copied ? t('donation.copied') : t('donation.copy')}
                    aria-label={
                      copied ? t('donation.copied') : t('donation.copy')
                    }
                    onClick={() => void handleCopy(activeWallet.address)}
                  >
                    {copied ? (
                      <IconCheck size="sm" />
                    ) : (
                      <IconCopy size="sm" />
                    )}
                    <span>
                      {copied ? t('donation.copied') : t('donation.copy')}
                    </span>
                  </button>
                </div>

                {'warning' in activeWallet && activeWallet.warning ? (
                  <p className="donation-warning" role="alert">
                    {activeWallet.warning}
                  </p>
                ) : null}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
