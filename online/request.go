package online

import (
	"context"
	"io"
	"log"
	"time"
	"zspure/tasks"

	"github.com/chromedp/chromedp"
)

func SendOnlineRequest(url string) (string, error) {
	silentLogger := log.New(io.Discard, "", 0)

	opts := append(
		chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("ignore-ssl-errors", true),
		chromedp.Flag("allow-insecure-localhost", true),
		chromedp.Flag("unsafely-treat-insecure-origin-as-secure", "*"),
	)

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	// Create context with SILENCED logging
	ctx, cancel := chromedp.NewContext(
		allocCtx,
		chromedp.WithErrorf(silentLogger.Printf),
		chromedp.WithDebugf(silentLogger.Printf),
		chromedp.WithLogf(silentLogger.Printf),
	)
	defer cancel()

	// Also silence DevTools events
	chromedp.ListenTarget(ctx, func(ev interface{}) {})

	ctx, cancel = context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	var html string

	if err := chromedp.Run(ctx,
		chromedp.Navigate(url),

		chromedp.WaitReady("body", chromedp.ByQuery),

		// Optional: wait for network to be almost silent
		chromedp.Sleep(5*time.Second),

		chromedp.OuterHTML("html", &html),
	); err != nil {
		return "", err
	}

	if err := tasks.DetectDeviceBaseURL(html); err != nil {
		return "", err
	}

	return html, nil
}
