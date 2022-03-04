import registration from "./registration";
import authentication from "./authentication";
import interopApp from "./interop-testing/interopApp";

export default async ({ expressApp }) => {
  await authentication({ app: expressApp });
  await registration({ app: expressApp });
  await interopApp({ app: expressApp });
};
