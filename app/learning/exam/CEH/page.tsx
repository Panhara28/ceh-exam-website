import LearningInterface from "@/components/learning-interface";
import { CEH_DUMP_QUESTIONS } from "@/data/questions";
import { Metadata } from "next";

export default function LearningExamCEH() {
  return (
    <>
      <LearningInterface learningData={CEH_DUMP_QUESTIONS} title="Certified Ethical Hacker (CEH) Exam Practice"/>
    </>
  );
}

export const metadata: Metadata = {
  title: "CEH Learning| Learn. Secure. Protect.",
  description:
    "your trusted cybersecurity learning platform in Cambodia. We empower individuals and organizations with practical knowledge, training, and tools to defend against digital threats. Explore hands-on tutorials, up-to-date cybersecurity news, and expert guidance to stay secure in an ever-evolving digital world.",
};
