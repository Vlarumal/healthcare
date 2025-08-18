import { forwardRef } from 'react';

export default forwardRef<HTMLDivElement>(function ScreenReaderAnnouncement(_props, ref) {
  return (
    <div
      ref={ref}
      aria-live="polite"
      aria-atomic="true"
      style={{
        position: 'absolute',
        width: '1px',
        height: '1px',
        overflow: 'hidden',
        clip: 'rect(0, 0, 0, 0)',
        whiteSpace: 'nowrap',
      }}
    />
  );
});