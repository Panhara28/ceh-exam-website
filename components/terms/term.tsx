"use client";

import type React from "react";

import { useState, useRef, useEffect } from "react";
import Image from "next/image";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";

import {
  ArrowDown,
  ThumbsUp,
  Cookie,
  Laugh,
  PartyPopper,
  Banana,
} from "lucide-react";
import { Confetti } from "@/components/confetti";

export default function TermsSection() {
  const [showAlert, setShowAlert] = useState(false);
  const [showConfetti, setShowConfetti] = useState(false);
  const [runningButton, setRunningButton] = useState(false);
  const [acceptedTerms, setAcceptedTerms] = useState(false);
  const runningButtonRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (showConfetti) {
      const timer = setTimeout(() => setShowConfetti(false), 5000);
      return () => clearTimeout(timer);
    }
  }, [showConfetti]);

  const handleRunningButton = (e: React.MouseEvent) => {
    if (runningButtonRef.current && !runningButton) {
      setRunningButton(true);

      // Move the button to a random position
      const maxX = window.innerWidth - 200;
      const maxY = window.innerHeight - 100;
      const randomX = Math.floor(Math.random() * maxX);
      const randomY = Math.floor(Math.random() * maxY);

      runningButtonRef.current.style.position = "fixed";
      runningButtonRef.current.style.left = `${randomX}px`;
      runningButtonRef.current.style.top = `${randomY}px`;
      runningButtonRef.current.style.zIndex = "50";
    }
  };

  const handleAccept = () => {
    setShowConfetti(true);
    setShowAlert(true);
  };

  return (
    <main className="container mx-auto px-4 py-8 max-w-4xl">
      {showConfetti && <Confetti />}

      <div className="flex flex-col items-center mb-8">
        <h1 className="text-4xl font-bold text-center mb-2">
          Terms of Service
        </h1>
        <p className="text-muted-foreground text-center mb-6">
          Please read our very serious and legally binding terms
        </p>
        <div className="flex items-center gap-2 text-sm text-muted-foreground mb-6">
          <ArrowDown className="animate-bounce" />
          <span>Scroll down to read our terms</span>
          <ArrowDown className="animate-bounce" />
        </div>
      </div>

      <ScrollArea className="h-[400px] border rounded-lg p-4 mb-8">
        <div className="space-y-6">
          <section>
            <h2 className="text-2xl font-semibold mb-3 flex items-center gap-2">
              <Cookie className="h-5 w-5" />
              Cookie Policy
            </h2>
            <p>
              By using this website, you agree that we can eat all your cookies.
              Not the digital ones, the actual cookies in your kitchen. We will
              send our Cookie Monster agents to your house at 3 AM to raid your
              cookie jar.
            </p>
          </section>

          <section>
            <h2 className="text-2xl font-semibold mb-3 flex items-center gap-2">
              <Laugh className="h-5 w-5" />
              Meme Ownership
            </h2>
            <p>
              Any memes you view on this website will be telepathically
              transferred to your brain. You are now legally obligated to laugh
              at them, even the bad ones. Failure to laugh will result in being
              sentenced to watch cat videos for 5 hours straight.
            </p>
          </section>

          <section>
            <h2 className="text-2xl font-semibold mb-3 flex items-center gap-2">
              <ThumbsUp className="h-5 w-5" />
              Social Media Integration
            </h2>
            <p>
              By clicking "Accept," you grant us permission to post embarrassing
              childhood photos on your social media accounts. We don't actually
              have these photos, but we're really good at Photoshop.
            </p>
          </section>

          <section>
            <h2 className="text-2xl font-semibold mb-3 flex items-center gap-2">
              <PartyPopper className="h-5 w-5" />
              Mandatory Fun
            </h2>
            <p>
              Users must have fun while browsing this website. Our advanced AI
              can detect if you're not smiling. Violators will be forced to
              watch compilation videos of people falling down until they laugh.
            </p>
          </section>

          <section>
            <h2 className="text-2xl font-semibold mb-3 flex items-center gap-2">
              <Banana className="h-5 w-5" />
              Banana Clause
            </h2>
            <p>
              For no particular reason, you must keep a banana on your person at
              all times while browsing this website. We cannot enforce this, but
              a banana will mysteriously appear in your fruit bowl tomorrow if
              you don't comply.
            </p>
          </section>

          <section>
            <p className="text-sm text-muted-foreground italic mt-8">
              Disclaimer: This entire terms of service is a joke. There are no
              actual terms. We're just having fun here. No bananas were harmed
              in the making of this website.
            </p>
          </section>
        </div>
      </ScrollArea>

      <div className="flex flex-col items-center gap-6">
        <div className="flex items-center space-x-2">
          <Checkbox
            id="terms"
            checked={acceptedTerms}
            onCheckedChange={(checked) => setAcceptedTerms(checked as boolean)}
          />
          <label
            htmlFor="terms"
            className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
          >
            I solemnly swear that I am up to no good and accept these ridiculous
            terms
          </label>
        </div>

        <div className="flex gap-4">
          <Button variant="outline" onMouseOver={handleRunningButton}>
            Decline
          </Button>

          <Button onClick={handleAccept} disabled={!acceptedTerms}>
            Accept
          </Button>
        </div>
      </div>

      <AlertDialog open={showAlert} onOpenChange={setShowAlert}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>You've been pranked! 🎉</AlertDialogTitle>
            <AlertDialogDescription>
              Congratulations! You just agreed to the most ridiculous terms of
              service ever. Don't worry, we won't actually steal your cookies...
              or will we? 🍪
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogAction>OK, you got me!</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </main>
  );
}
