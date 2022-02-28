import registration from "./registration";
import authentication from "./authentication";

export default async ({ expressApp }) => {
  await authentication({ app: expressApp });
  await registration({ app: expressApp });
};
